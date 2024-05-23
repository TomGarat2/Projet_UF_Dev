// static/js/encrypt_decrypt.js
$(document).ready(function() {
    $('#encrypt-form').on('submit', function(e) {
        e.preventDefault(); // Empêche le rechargement de la page
        var form = $(this);
        var url = form.attr('action');
        var formData = new FormData(this);
        $.ajax({
            type: 'POST',
            url: url,
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                $('#result').html(response);
                if (url.includes('encrypt')) {
                    $('#keysList').append('<li>' + response.split(':')[1].trim() + '</li>');
                }
            },
            error: function(response) {
                $('#result').html('Une erreur est survenue.');
            }
        });
    });

    $('#decrypt-form').on('submit', function(e) {
        e.preventDefault(); // Empêche le rechargement de la page
        var form = $(this);
        var url = form.attr('action');
        var formData = new FormData(this);
        $.ajax({
            type: 'POST',
            url: url,
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                $('#result').html(response);
            },
            error: function(response) {
                $('#result').html('Une erreur est survenue.');
            }
        });
    });
});