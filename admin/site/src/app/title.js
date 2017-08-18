angular
  .module('app')
  .component('fountainTitle', {
    templateUrl: 'app/title.html',
    controller: MainSection
  });

/** @ngInject */
function MainSection($cookies, adminService) {
  var vm = this;
  vm.adminService = adminService;
  vm.adminService.init();
}
