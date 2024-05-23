// app.js
$(document).ready(function() {
    // Gérer la soumission des formulaires avec Ajax
    $('form').on('submit', function(e) {
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
            success: function(data) {
                if (url.includes('encrypt')) {
                    $('#encryptionKey').text("Clé de cryptage: " + data);
                } else {
                    $('#decryptedContent').text("Contenu décrypté: " + data);
                }
                $('#keyInput').show();
            }
        });
    });

    // Récupérer l'historique des clés
    function fetchKeys() {
        $.ajax({
            type: 'GET',
            url: '/key-history',
            success: function(keys) {
                var list = $('#keysList');
                list.empty();  // Vide la liste actuelle
                keys.forEach(function(key) {
                    if (key) {
                        list.append('<li>' + key + '</li>');
                    }
                });
            }
        });
    }

    fetchKeys();  // Appelle cette fonction au chargement de la page
});