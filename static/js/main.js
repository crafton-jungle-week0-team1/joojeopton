import $ from 'jquery';
$(document).ready(function() {
    $('#sortDropdownButton').on('click', function(e) {
        e.stopPropagation();
        $('#sortDropdown').toggleClass('hidden');
    });

    $(document).on('click', function(e) {
        if (!$(e.target).closest('#sortDropdownButton').length) {
            $('#sortDropdown').addClass('hidden');
        }
    });
    $('#myButton').on('click', function() {
        console.log('Button clicked!');
        goto_joojeop();
    });
    function goto_joojeop() {
        $.ajax({
            type: "GET",
            url: "/joojeop",
            success: function (response) {
                alert("Success");
            }
        });
    }
});
