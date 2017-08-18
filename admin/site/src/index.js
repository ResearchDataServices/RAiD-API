angular
  .module('app', ['ui.router', 'ngCookies'])
  .service('adminService', AdminService);

function AdminService($cookies) {
  var service = this;
  service.session = false;

  service.init = function () {
    var cookie = $cookies.getObject('credential');
    if (cookie) {
      service.session = true;
      service.credential = cookie;
    }
  };

  service.setCookie = function (credential) {
    $cookies.putObject('credential', credential);
    service.session = true;
  };

  service.end = function () {
    $cookies.remove('credential');
    service.session = false;
  };
}
