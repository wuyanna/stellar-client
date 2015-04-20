'use strict';
/* exported STELLAR_CLIENT_REVISION */
/* jslint camelcase: false */
var STELLAR_CLIENT_REVISION = '_GIT_REVISION_GOES_HERE_';

console.log("%cStop!", "color:white; background:red; font-size: 16pt");
console.log("%cThis is browser feature intended for developers. If someone told you to copy-paste something here, it is a scam and will give them access to your money!", "font-size: 14pt");

var stellarClient = angular.module('stellarClient', [
  'angularMoment',
  'bruteRequest',
  'facebook',
  'filters',
  'ipCookie',
  'ngGrid',
  'ngRaven',
  'ngRoute',
  'debounce',
  'singletonPromise',
  'ui.router',
  'vr.passwordStrength',
  'ngClipboard',
  'vcRecaptcha',
  'ja.qr',
  'angulartics',
  'angulartics.segment.io',
  'stellarApi'
]);

/**
 * DEBUG TOOL!  $get makes it easy to retrieve an instance from the angular
 * dependency injection system.
 *
 * @param  {string} dependency the dependency to retrieve, by name
 * @return {object}            the resolved dependency
 */
window.$get = function (dependency) {
  return angular.element(document).injector().get(dependency);
};





stellarClient.config(function($httpProvider, $stateProvider, $urlRouterProvider, RavenProvider, ngClipProvider, FacebookProvider) {

  FacebookProvider.init(Options.APP_ID);

  ngClipProvider.setPath("bower_components/zeroclipboard/dist/ZeroClipboard.swf");

  if(Options.REPORT_ERRORS !== true) {
    RavenProvider.development(true);
  }

  sjcl.random.startCollectors();

  $httpProvider.interceptors.push('bruteRequestInterceptor');

  $stateProvider
    .state('login', {
      url:         '/login',
      templateUrl: 'states/login.html',
      authenticate: false
    })
    .state('login_v1', {
      templateUrl: 'states/login_v1.html',
      authenticate: false,
      // There is a bug in angular-ui-router because of which we cannot pass
      // an array ['username'] here. Instead we need to pass this object.
      // Check out angular-ui-router.js:
      //
      // // Filter parameters before we pass them to event handlers etc.
      // toParams = filterByKeys(objectKeys(to.params), toParams || {});
      params: {'username': 0}
    })
    .state('login_v2', {
      templateUrl: 'states/login_v2.html',
      authenticate: false,
      params: {'username': 0, 'totpRequired': 0}
    })
    .state('recovery-v2', {
      url:         '/recovery-v2',
      templateUrl: 'states/recovery_v2.html',
      authenticate: false
    })
    .state('recovery', {
      url:         '/recovery',
      templateUrl: 'states/recovery.html',
      authenticate: false
    })
    .state('username-recovery', {
      url:         '/username-recovery',
      templateUrl: 'states/username_recovery.html',
      authenticate: false
    })
    .state('lost-2fa-device', {
      url:         '/lost-2fa-device',
      templateUrl: 'states/lost_2fa_device.html',
      authenticate: false
    })
    .state('register', {
      url:         '/register?inviteCode',
      templateUrl: 'states/register.html',
      authenticate: false
    })
    .state('logout', {
      url:         '/logout',
      authenticate: true
    })
    .state('dashboard', {
      url:         '/dashboard',
      templateUrl: 'states/dashboard.html',
      authenticate: true
    })
    .state('change_password', {
      url:         '/change_password',
      templateUrl: 'states/change_password.html',
      authenticate: true
    })
    .state('change_password_v2', {
      templateUrl: 'states/change_password_v2.html',
      authenticate: false,
      params: {'username': 0, 'masterKey': 0, 'recoveryCode': 0, 'totpRequired': false}
    })
    .state('settings', {
      url:         '/settings',
      templateUrl: 'states/settings.html',
      authenticate: true,
      params: {'migrated-wallet-recovery': false}
    })
    .state('invites', {
      url:         '/invites',
      templateUrl: 'states/invites.html',
      authenticate: true
    })
    .state('style-docs', {
      url:         '/style-docs',
      templateUrl: 'states/style-docs.html'
    })
    .state('trading', {
      url:         '/trading',
      templateUrl: 'states/trading.html',
      authenticate: true
    })
    .state('trade', {
      url:         '/trade',
      templateUrl: 'states/trade.html',
      authenticate: true
    })
  ;

  // $urlRouterProvider.otherwise('/dashboard');

});
  
stellarClient.run(function($location, $state, ipCookie, session){
  Omlet.ready(function() {

  

  if (Omlet.scope.identity == undefined) {
    initializeStellar(null);
    return;
  }
  var user = Omlet.scope.identity.account;
  var config = {
                
                    type: 'federation',
                    domain: Options.DEFAULT_FEDERATION_DOMAIN,
                    destination: user,
                    // DEPRECATED "destination" is a more neutral name for this field
                    //   than "user"
                    user: user,
                    omletId: user
                
            };
            $.get(Options.API_SERVER + '/federation', config)
            .done(function (data) {
                if ("object" === typeof data &&
                    "object" === typeof data.federation_json &&
                    data.federation_json.type === "federation_record" &&
                    (data.federation_json.user === user ||
                        data.federation_json.destination === user) &&
                    data.federation_json.domain === Options.DEFAULT_FEDERATION_DOMAIN) {
                    initializeStellar(data.federation_json.stellar_user);
                } else if ("string" === typeof data.error) {
                    initializeStellar(null);
                } else {
                    initializeStellar(null);
                }
            })
            .fail(function () {
                initializeStellar(null);
            });
});

 var initializeStellar = function(name) {
  var atRoot    = _.isEmpty($location.path());
  // var firstTime = !ipCookie("weve_been_here_before");
  var firstTime = (name == null);
  var forceToRegister = atRoot && firstTime;
    session.deviceKey = Omlet.scope.device_key;

    if(forceToRegister) {
      $state.transitionTo('register');
      ipCookie("weve_been_here_before", "true", {expires: new Date('01 Jan 2030 00:00:00 GMT')});
    } else {
      session.username = name;
      
      session.usepin = true;  //TODO: get from server;
      $state.transitionTo('dashboard');
    }

  };
});

stellarClient.run(function($rootScope, $timeout, StellarNetwork, ActionLink){
  ActionLink.recognize();

  $rootScope.$on('$stateChangeStart', function(event, toState, toParams, fromState, fromParams){
    ActionLink.recognize();
  });

  $rootScope.$on('$stateChangeSuccess', function(event, toState, toParams, fromState, fromParams){
    if(toState.authenticate) {
      StellarNetwork.ensureConnection().then(function() {
        // HACK: Timeout required to allow templates' controllers initialize and start listening.
        $timeout(ActionLink.process, 0);
      });
    }
  });
});

stellarClient.run(function($rootScope, $state, $timeout, ipCookie, session, FlashMessages){
  
  $rootScope.$on('$stateChangeStart', function(event, toState, toParams, fromState, fromParams){
    if(toState.name === 'logout' && session.get('loggedIn')) {
      event.preventDefault();
      session.logout();

      return;
    }

    // If the user is navigating to a state that requires no authentication
    // send them to the dashboard if they are logged in.
    if(!toState.authenticate && session.get('loggedIn')) {
      event.preventDefault();
      $state.transitionTo('dashboard');

      return;
    }

    // If the user is navigating to a state that requires authentication
    // try to log them in from storage. If that fails send them to the login page.
    if(!toState.authenticate || !session.get('loggedIn')) {
      var wallet;

      if(session.isPersistent() && !session.get('loggedIn')) {
        wallet = session.getWalletFromStorage();
      }

      if(wallet) {
        session.login(wallet);
      } else if(toState.authenticate) {
        // Redirect authenticated routes to login if we are unable to login from local.
        event.preventDefault();
        $state.transitionTo('login');
      }

      return;
    }

    FlashMessages.dismissAll();
  });
});

stellarClient.config(function() {
  // Configure BigNumber to never return exponential notation
  BigNumber.config({ EXPONENTIAL_AT : 1e+9 });
});


// Analytics
stellarClient.config(function ($analyticsProvider) {
  $analyticsProvider.virtualPageviews(true);
  $analyticsProvider.firstPageview(true);
});
