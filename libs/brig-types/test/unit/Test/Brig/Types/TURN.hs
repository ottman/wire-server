{-# LANGUAGE OverloadedStrings #-}

module Test.Brig.Types.TURN where

import Brig.Types.TURN hiding (turnURI)
import Control.Monad.IO.Class
import Data.Aeson
import Data.Misc
import Test.Brig.Types.Arbitrary
import Test.Tasty
import Test.Tasty.QuickCheck

tests :: TestTree
tests = testGroup "TURN"
    [ testProperty "TurnURI: decode . encode = id" turnURIid
    ]

turnURIid :: TurnURI -> Property
turnURIid t = Just t === (decode . encode) t
