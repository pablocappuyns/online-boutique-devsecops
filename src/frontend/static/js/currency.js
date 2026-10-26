// Envía el formulario de moneda al cambiar la selección. Sustituye al manejador onchange en
// línea para que la Content-Security-Policy no tenga que permitir scripts en línea.
document.addEventListener('DOMContentLoaded', function () {
  var select = document.getElementById('currency_select');
  if (select) {
    select.addEventListener('change', function () {
      document.getElementById('currency_form').submit();
    });
  }
});
