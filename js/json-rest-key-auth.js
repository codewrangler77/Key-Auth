(function () {

    if ( !window.jsonRestKeyAuth ) {
        window.jsonRestKeyAuth = {};
    }

    function makeRandomString ( ofLength ) {
        var pool = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtWwXxYyZz098*76^54321!`~-';
        var newString = [];

        while ( newString.length < ofLength ) {
            newString.push ( pool.charAt ( Math.floor ( Math.random () * pool.length ) ) );
        }

        return newString.join ( '' );
    }

    window.jsonRestKeyAuth.generateAPIKeyToField = function ($field) {
        if( $field.length > 0) {
            $field.val('JRKAA::' + makeRandomString ( 12 ));
        }
    };

    window.jsonRestKeyAuth.generateSharedSecret = function ($field) {
        if( $field.length > 0) {
            $field.val('JRKSS::' + makeRandomString ( 32 ));
        }
    };
}) ();