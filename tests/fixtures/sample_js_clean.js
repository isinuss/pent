// Clean JavaScript file with no secrets
(function() {
    "use strict";

    function calculateTotal(items) {
        return items.reduce(function(sum, item) {
            return sum + item.price * item.quantity;
        }, 0);
    }

    function formatCurrency(amount) {
        return "$" + amount.toFixed(2);
    }

    document.addEventListener("DOMContentLoaded", function() {
        var form = document.getElementById("checkout-form");
        if (form) {
            form.addEventListener("submit", function(e) {
                e.preventDefault();
                var total = calculateTotal(window.cartItems || []);
                document.getElementById("total").textContent = formatCurrency(total);
            });
        }
    });
})();
