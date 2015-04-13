'use strict';

angular.module('stellarClient').controller('LoginV1Ctrl', function($rootScope, $scope, $http, $state, $stateParams, $q, session, invites, Wallet, singletonPromise, usernameProof) {
  setTimeout(function() {
    angular.element('#password')[0].focus();
  }, 200);
  $scope.pinDigit = new Array; // Array

  $scope.recordDigitAndMove = function(currentId, nextFieldID) {
    var i = parseInt(currentId.substr(currentId.length - 1)) - 1;
    // $scope.pinDigit[i] = field.value;
    if (document.getElementById(currentId).value.length == 1 && nextFieldID != null) {
        document.getElementById(nextFieldID).focus();
    }
  };

    function keyHash(key, token) {
    var hmac = new sjcl.misc.hmac(key, sjcl.hash.sha512);
    return sjcl.codec.hex.fromBits(sjcl.bitArray.bitSlice(hmac.encrypt(token), 0, 256));
  };

var cryptConfig = {
  cipher : 'aes',
  mode   : 'ccm',
  ts     : 64,   // tag length
  ks     : 256,  // key size
  iter   : 1000  // iterations (key derivation)
};
/**
 * Encrypt data
 *
 * @param {string} key
 * @param {string} data
 */
function extend() {
    var target = {}

    for (var i = 0; i < arguments.length; i++) {
        var source = arguments[i]

        for (var key in source) {
            if (source.hasOwnProperty(key)) {
                target[key] = source[key]
            }
        }
    }

    return target
}
function encrypt(key, data) {
  key = sjcl.codec.hex.toBits(key);

  var opts = extend(true, {}, cryptConfig);

  var encryptedObj = JSON.parse(sjcl.encrypt(key, data, opts));
  var version = [sjcl.bitArray.partial(8, 0)];
  var initVector = sjcl.codec.base64.toBits(encryptedObj.iv);
  var ciphertext = sjcl.codec.base64.toBits(encryptedObj.ct);

  var encryptedBits = sjcl.bitArray.concat(version, initVector);
  encryptedBits = sjcl.bitArray.concat(encryptedBits, ciphertext);

  return sjcl.codec.base64.fromBits(encryptedBits);
};

/**
 * Decrypt data
 *
 * @param {string} key
 * @param {string} data
 */

function decrypt(key, data) {
  
  key = sjcl.codec.hex.toBits(key);
  var encryptedBits = sjcl.codec.base64.toBits(data);

  var version = sjcl.bitArray.extract(encryptedBits, 0, 8);

  if (version !== 0) {
    throw new Error('Unsupported encryption version: '+version);
  }

  var encrypted = extend(true, {}, cryptConfig, {
    iv: sjcl.codec.base64.fromBits(sjcl.bitArray.bitSlice(encryptedBits, 8, 8+128)),
    ct: sjcl.codec.base64.fromBits(sjcl.bitArray.bitSlice(encryptedBits, 8+128))
  });

  return sjcl.decrypt(key, JSON.stringify(encrypted));
};

  $scope.attemptLogin = function() {

    var pin = "";
      for(var i = 0; i < 4; i++) {
        if ($scope.pinDigit[i].length < 1) {
          validInput = false;
          $scope.errors.secretErrors.push('Invalid pin.');
          break;
        }
        pin += $scope.pinDigit[i];
      }
    var deviceKeyIndex = keyHash("1", session.deviceKey);
    var deviceKeyEnc = keyHash("2", session.deviceKey);
    var params = {
      username: $stateParams.username,
      device: deviceKeyIndex,
      lookup: keyHash(pin, deviceKeyEnc)
    };
    $http.post(Options.API_SERVER + '/user/pinLogin', params)
      .success(function(body) {
        var pwd = decrypt(deviceKeyEnc, body.data.encryptedWallet);
        $scope.password = pwd;
        $scope.attemptLoginWithPwd();
      })
      .error(function(body, status) {
        switch(status) {

          default:
            $scope.loginError = 'Invalid Pin.';
        }
      });

    return true;
  };

  $scope.totpRequired = $stateParams.totpRequired;

  // HACK: Perform AJAX login, but send a POST request to a hidden iframe to
  // coax Chrome into offering to remember the password.
  $scope.attemptLoginWithPwd = function() {
    var params = {
      server: Options.WALLET_SERVER+'/v2',
      username: $stateParams.username.toLowerCase()+'@stellar.org',
      password: $scope.password
    };

    $scope.asyncLogin(params).catch(function(e) {
      var forbiddenError = "Login credentials are incorrect.";
      if ($stateParams.username === $stateParams.username.toLowerCase()) {
        $scope.loginError = forbiddenError;
      } else {
        // If username contains uppercase letters we need to repeat the process with
        // username passed by the user. It's because of the bug in change-password-v2-controller.
        // Username was not toLowerCase()'d there thus calculated masterKey was incorrect.
        // Fixes #1102.
        params.username = $stateParams.username;
        $scope.asyncLogin(params).catch(function(e) {
          $scope.loginError = forbiddenError;
        });
      }
    });
    return true;
  };

  $scope.asyncLogin = singletonPromise(function(params) {
    $scope.loginError = null;

    if (!$scope.password || ($scope.totpRequired && !$scope.totpCode)) {
      $scope.loginError = "Password ";
      if ($scope.totpRequired) {
        $scope.loginError += "and TOTP code ";
      }
      $scope.loginError += "cannot be blank.";
      return $q.reject();
    }

    if ($scope.totpRequired) {
      params = _.extend(params, {
        totpCode: $scope.totpCode
      });
    }

    /**
    * We're checking if a `wallet` is affected by a bug fixed in #1113.
    * If it is, we're adding a `changePasswordBug` property to `mainData`
    * to indicate whether we should display a flash message to a user.
    * @param wallet StellarWallet
    */
    function checkIfAffectedByChangePasswordBug(wallet) {
      var bugDeploy   = new Date('2014-11-17'); // Bug introduced
      var bugResolved = new Date('2015-01-12'); // Bugfix deployed
      var updatedAt   = new Date(wallet.getUpdatedAt());
      if (updatedAt >= bugDeploy && updatedAt <= bugResolved) {
        var mainData = session.get('wallet').mainData;
        if (!mainData.changePasswordBug ||
          mainData.changePasswordBug && mainData.changePasswordBug !== 'resolved') {
          mainData.changePasswordBug = 'show-info';
          return session.syncWallet('update');
        }
      }
    }

    // We don't have to run $scope.$apply because it's wrapped in singletonPromise
    return StellarWallet.getWallet(params)
      .tap(function(wallet) {
        if ($scope.rememberMe) {
          session.rememberUser();
        }
        session.login(new Wallet({
          version: 2,
          id: wallet.getWalletId(),
          key: wallet.getWalletKey(),
          keychainData: wallet.getKeychainData(),
          mainData: wallet.getMainData(),
          walletV2: wallet
        }));
      })
      .then(checkIfAffectedByChangePasswordBug)
      .then(function() {
        $state.go('dashboard');
      })
      .catch(StellarWallet.errors.TotpCodeRequired, function() {
        $scope.loginError = "2-Factor-Authentication code is required to login.";
      }).catch(StellarWallet.errors.ConnectionError, function() {
        $scope.loginError = "Error connecting wallet server. Please try again later.";
      }).catch(function(e) {
        if (e.name && e.name === 'Forbidden') {
          return $q.reject(e);
        }
        Raven.captureMessage('StellarWallet.getWallet unknown error', {
          extra: {
            error: e
          }
        });
        $scope.loginError = "Unknown error.";
      });
  });

});