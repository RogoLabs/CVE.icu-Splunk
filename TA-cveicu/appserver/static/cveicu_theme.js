/**
 * CVE.ICU Theme Manager
 * 
 * Applies user's theme preference (light/dark) to dashboards.
 * Reads preference from REST endpoint and applies CSS class.
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    'use strict';
    
    // Function to apply theme
    function applyTheme(theme) {
        var $dashboard = $('.dashboard-body');
        var $html = $('html');
        
        if (theme === 'dark') {
            $html.addClass('dark');
            $dashboard.addClass('dark');
            // Update dashboard theme attribute if possible
            $('[data-view="views/shared/splunkbar/Master"]').addClass('dark');
        } else {
            $html.removeClass('dark');
            $dashboard.removeClass('dark');
            $('[data-view="views/shared/splunkbar/Master"]').removeClass('dark');
        }
        
        console.log('CVE.ICU theme applied:', theme);
    }
    
    // Function to fetch theme from settings
    function fetchAndApplyTheme() {
        $.ajax({
            url: '/en-US/splunkd/__raw/servicesNS/nobody/TA-cveicu/TA_cveicu_setup/github_settings?output_mode=json',
            type: 'GET',
            dataType: 'json',
            success: function(data) {
                var theme = 'light'; // default
                try {
                    if (data && data.entry && data.entry[0] && data.entry[0].content) {
                        theme = data.entry[0].content.theme || 'light';
                    }
                } catch (e) {
                    console.log('Using default theme');
                }
                applyTheme(theme);
            },
            error: function() {
                // On error, use light theme
                applyTheme('light');
            }
        });
    }
    
    // Also check URL parameter for immediate override
    function getUrlTheme() {
        var urlParams = new URLSearchParams(window.location.search);
        return urlParams.get('theme');
    }
    
    // Apply theme on page load
    $(document).ready(function() {
        var urlTheme = getUrlTheme();
        if (urlTheme) {
            applyTheme(urlTheme);
        } else {
            fetchAndApplyTheme();
        }
    });
});
