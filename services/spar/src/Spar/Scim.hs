{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE LambdaCase #-}

-- TODO remove (orphans can be avoided by only implementing functions here, and gathering them
-- in the instance near the Spar type; alternatively, @hscim@ could be changed)
{-# OPTIONS_GHC
    -Wno-missing-methods
    -Wno-orphans
  #-}

-- | An implementation of the SCIM API for doing bulk operations with users.
--
-- See <https://en.wikipedia.org/wiki/System_for_Cross-domain_Identity_Management>
--
-- = SCIM user creation flow
--
-- When a user is created via SCIM, a SAML user identity has to be created with it. Currently
-- we don't allow SCIM users without SAML user identities.
--
-- Creating these two user identities (SCIM and SAML) together requires constructing a
-- 'UserRef' from the SCIM request, which is then stored by 'Spar.Data.insertUser'.
--
-- The 'UserRef' consists of:
--
--   * tenant (the url-shaped ID the IdP assigns to itself);
--
--   * subject (usually an email, or an unstructured nickname, or a few more obscure
--     alternatives).
--
-- /Tenant:/ if there is only one IdP for the current team, the tenant can be found by calling
-- 'getIdPConfigsByTeam' and looking up @^. idpMetadata . edIssuer@ on the result. If there is
-- more than one IdP, we need a way to associate user creation requests with specific IdPs.
-- Currently we disallow teams with more than one IdP.
--
-- /Subject:/ there are different reasonable ways to pick a subject for a user; this should be
-- configurable in the team settings page (e.g. a choice of one field from the SCIM user
-- schema, optionally transformed with one of a few hard-coded functions). A simple default
-- could be "take the email address, and type it as an email address", or in saml2-web-sso
-- pseudo-code: @\email -> entityNameID (parseURI ("email:" <> renderEmail email))@.

module Spar.Scim
    (
      -- * Reexports
      module Spar.Scim.Types
    , module Spar.Scim.Auth
    , module Spar.Scim.User

      -- * API implementation
    , apiScim
    ) where

import Imports

import Control.Lens
import Control.Monad.Catch (try)
import Control.Monad.Except
import Data.String.Conversions (cs)
import Servant
import Servant.API.Generic
import Spar.App (Spar(..), Env)
import Spar.Error (SparError, sparToServantErr)
import Spar.Scim.Types
import Spar.Scim.Auth
import Spar.Scim.User
import Spar.Types

import qualified SAML2.WebSSO as SAML

import qualified Web.Scim.Class.Group             as Scim.Group
import qualified Web.Scim.Handler                 as Scim
import qualified Web.Scim.Schema.Error            as Scim
import qualified Web.Scim.Server                  as Scim

import qualified Web.Scim.Capabilities.MetaSchema as Scim.Meta

-- | SCIM config for our server.
--
-- TODO: the 'Scim.Meta.empty' configuration claims that we don't support filters, but we
-- actually do; it's a bug in hscim
configuration :: Scim.Meta.Configuration
configuration = Scim.Meta.empty

apiScim :: ServerT APIScim Spar
apiScim = hoistScim (toServant (Scim.siteServer configuration))
     :<|> apiScimToken
  where
    hoistScim = hoistServer (Proxy @(Scim.SiteAPI ScimToken))
                            (wrapScimErrors . toSpar)

    -- Unwrap the 'ScimHandler'
    toSpar :: Scim.ScimHandler Spar a -> Spar a
    toSpar = Scim.fromScimHandler
             (throwError . SAML.CustomServant . Scim.scimToServantErr)

    -- Wrap all errors into the format required by SCIM.
    --
    -- FIXME: this doesn't catch impure exceptions (e.g. thrown with 'error').
    -- Let's hope that SCIM clients can handle non-SCIM-formatted errors
    -- properly. See <https://github.com/haskell-servant/servant/issues/1022>
    -- for why it's hard to catch impure ex
    wrapScimErrors :: Spar a -> Spar a
    wrapScimErrors = over (_Spar . mapped) $ \io ->
        try @_ @SomeException io <&> \case
            -- We caught an exception that's not a Spar exception. It is
            -- wrapped into SCIM.serverError and rethrown.
            Left someException ->
                Left . SAML.CustomServant . Scim.scimToServantErr $
                Scim.serverError (cs (displayException someException))
            -- We caught a 'CustomServant' exception. It should be left as-is
            -- because by now all SCIM errors have become 'CustomServant' errors
            -- (thanks to 'toSpar') and we don't want to wrap them *again*.
            Right (Left (SAML.CustomServant x)) ->
                Left (SAML.CustomServant x)
            -- We caught some other Spar exception. It should be wrapped into
            -- SCIM.serverError and rethrown.
            Right (Left sparError) ->
                Left . SAML.CustomServant . Scim.scimToServantErr $
                Scim.serverError (cs (errBody (sparToServantErr sparError)))
            -- No exceptions! Good.
            Right (Right x) ->
                Right x

    -- This isomorphism unwraps the Spar stack (Spar . ReaderT . ExceptT) into a
    -- newtype-less form that's easier to work with.
    _Spar :: Iso' (Spar a) (Env -> IO (Either SparError a))
    _Spar = coerced

instance Scim.Group.GroupDB Spar where
  -- TODO
