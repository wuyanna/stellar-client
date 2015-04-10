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
  // HACK: Perform AJAX login, but send a POST request to a hidden iframe to
  // coax Chrome into offering to remember the password.
  $scope.attemptLogin = function() {
    $scope.asyncLogin();
    return true;
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

  $scope.getWalletId = function() {
    var deferred = $q.defer();
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
      lookup: keyHash(data.pin, deviceKeyEnc)
    };
    $http.post(Options.API_SERVER + '/user/pinLogin', params)
      .success(function(body) {
        var wid = decrypt(deviceKeyEnc, body.data.encryptedWallet);
        deferred.resolve(wid);
      })
      .error(function(body, status) {
        switch(status) {

          default:
            $scope.loginError = 'Invalid Pin.';
        }
        deferred.reject();
      });

    return deferred.promise;
  };

  $scope.asyncLogin = singletonPromise(function() {
    $scope.loginError = null;
    if (!$scope.password) {
      return $q.reject("Password cannot be blank");
    }
    return getWalletId()
      .then(performLogin)
      .then(migrateWallet)
      .then(markMigrated)
      .then(login)
      .then(updateApiRecover)
      .then(claimInvite)
      .then(function() {
        var deferred = $q.defer();

        // Store needsRecoveryCodeReset flag in the wallet but only if migrated user has recovery
        var data = {
          params: {
            username: session.get('username'),
            updateToken: session.get('wallet').keychainData.updateToken
          }
        };
        $http.get(Options.API_SERVER + "/user/settings", data)
          .success(function (response) {
            if (response.data.hasRecovery) {
              var wallet = session.get('wallet');
              wallet.mainData.needsRecoveryCodeReset = true;
              session.syncWallet('update')
                .then(function() {
                  deferred.resolve();
                });
            } else {
              deferred.resolve();
            }
          })
          .error(function (response) {
            deferred.resolve();
          });

        return deferred.promise;
      })
      .then(function() {
        $state.go('dashboard');
      });
  });

  var oldWalletId;
  function performLogin(id) {
    var deferred = $q.defer();

    oldWalletId = id;

    $http.post(Options.WALLET_SERVER + '/wallets/show', {id: id})
      .success(function(body) {
        deferred.resolve(Wallet.open(body.data, id, $stateParams.username, $scope.password));
      })
      .error(function(body, status) {
        switch(status) {
          case 404:
            $scope.loginError = 'Invalid username or password.';
            break;
          case 0:
            $scope.loginError = 'Unable to contact the server.';
            break;
          default:
            $scope.loginError = 'An error occurred.';
        }
        deferred.reject();
      });

    return deferred.promise;
  }

  function migrateWallet(wallet) {
    /* jshint camelcase:false */
    
    var deferred = $q.defer();

    // Migrate signingKeys
    var seed = new stellar.Seed().parse_json(wallet.keychainData.signingKeys.secret);
    var keyPair = seed.get_key();
    var address = keyPair.get_address();

    var publicKey = nacl.util.encodeBase64(keyPair._pubkey);
    var secretKey = nacl.util.encodeBase64(keyPair._secret);

    var signingKeys = {
      address: address.to_json(),
      secret: seed.to_json(),
      secretKey: secretKey,
      publicKey: publicKey
    };

    wallet.keychainData.signingKeys = signingKeys;

    var proof = usernameProof(wallet.keychainData.signingKeys, $stateParams.username);
    proof.migrated = true; // This is a migrated wallet

    // Perform a migration
    StellarWallet.createWallet({
      server: Options.WALLET_SERVER+'/v2',
      username: $stateParams.username.toLowerCase()+'@stellar.org',
      password: $scope.password,
      publicKey: signingKeys.publicKey,
      keychainData: JSON.stringify(wallet.keychainData),
      mainData: JSON.stringify(wallet.mainData),
      usernameProof: proof
    }).then(function(wallet) {
      var w = new Wallet({
        version: 2,
        id: wallet.getWalletId(),
        key: wallet.getWalletKey(),
        keychainData: wallet.getKeychainData(),
        mainData: wallet.getMainData(),
        walletV2: wallet
      });
      deferred.resolve(w);
    }).catch(function(e) {
      if (e.name === 'ConnectionError') {
        $scope.loginError = 'Connection error. Please try again later.';
      } else {
        Raven.captureMessage('StellarWallet.createWallet unknown error', {
          extra: {
            id: oldWalletId,
            error: e
          }
        });
        $scope.loginError = 'Unknown error. Please try again later.';
      }

      deferred.reject();
      throw e;
    }).finally(function() {
      $scope.$apply();
    });

    return deferred.promise;
  }

  function markMigrated(wallet) {
    var deferred = $q.defer();

    // Mark migrated
    $http.post(Options.WALLET_SERVER + "/wallets/mark_migrated", {
      id: oldWalletId,
      authToken: wallet.keychainData.authToken
    }).success(function(response) {
      deferred.resolve(wallet);
    }).error(function(response) {
      Raven.captureMessage('Error response from /wallets/mark_migrated', {
        extra: {
          id: oldWalletId,
          response: response
        }
      });
      deferred.reject();
    });

    return deferred.promise;
  }

  function login(wallet) {
    if ($scope.rememberMe) {
      session.rememberUser();
    }
    session.login(wallet);
  }

  function updateApiRecover() {
    // Recovery code is no longer valid.
    $http.post(Options.API_SERVER + "/user/setrecover", {
      username: session.get('username'),
      updateToken: session.get('wallet').keychainData.updateToken,
      recover: false
    });
  }

  function claimInvite() {
    if(session.get('inviteCode')) {
      invites.claim(session.get('inviteCode'))
        .success(function (response) {
          $rootScope.$broadcast('invite-claimed');
        });
    }
  }
});