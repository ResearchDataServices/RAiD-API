angular
  .module('app')
  .component('fountainTokens', {
    templateUrl: 'app/tokens/tokens.html',
    controller: tokensController
  });

/** @ngInject */
function tokensController($http) {
  var vm = this;

  $http
    .get('app/tokens/tokens.json')
    .then(function (response) {
      vm.tokens = response.data;
    });
}
