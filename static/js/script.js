$(document).ready(function(){
    $('.sidenav').sidenav();
  });

$(document).ready(function(){
  $('.collapsible').collapsible();
});

$('#reviewarea').val('New Text');
  M.textareaAutoResize($('#review-area'));

  
$(document).ready(function(){
  $('select').formSelect();
});