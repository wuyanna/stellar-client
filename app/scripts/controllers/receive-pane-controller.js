'use strict';

var sc = angular.module('stellarClient');

sc.controller('ReceivePaneCtrl', function($scope, session) {
  $scope.showAddress = false;

  $scope.currentAddress = function() {
    return session.get('address');
  };

  $scope.toggleAddress = function() {
  	$scope.showAddress = !$scope.showAddress;
  };

  $scope.askMoney = function() {
  	var rdl = Omlet.createRDL({
            noun: "ask for money",
            displayTitle: "Please send me Stellar",
            displayThumbnailUrl: "https://encrypted-tbn2.gstatic.com/images?q=tbn:ANd9GcQ49Ppvn_MCPaIzkCZvNld3_b-IbRz4vTHZts-o1J4KU_NrKj3TzQ",
            displayText: "Hi, can you send me stellar?",
            json: null,
            webCallback: null,
            callback: window.location.href,
        });
    Omlet.exit(rdl);
  };
});
