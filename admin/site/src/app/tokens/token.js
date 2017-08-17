angular
  .module('app')
  .component('fountainToken', {
    templateUrl: 'app/tokens/token.html',
    bindings: {
      token: '<'
    }
  });
