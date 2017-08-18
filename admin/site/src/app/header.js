angular
  .module('app')
  .component('fountainHeader', {
    templateUrl: 'app/header.html',
    controller: HeaderSection
  });

  /** @ngInject */
function HeaderSection($cookies, adminService) {
  var vm = this;
  vm.adminService = adminService;
}
