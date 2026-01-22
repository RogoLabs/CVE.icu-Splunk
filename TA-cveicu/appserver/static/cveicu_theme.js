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
    
    // Configuration
    var CONFIG = {
        REST_ENDPOINT: '/servicesNS/nobody/TA-cveicu/ta_cveicu/ta_cveicu_settings/github_settings'
    };
    
    /**
     * Get the current locale from the URL path
     */
    function getLocale() {
        var match = window.location.pathname.match(/^\/([a-z]{2}-[A-Z]{2})\//);
        return match ? match[1] : 'en-US';
    }
    
    /**
     * Build the full URL with locale prefix
     */
    function buildUrl(path) {
        var locale = getLocale();
        return '/' + locale + '/splunkd/__raw' + path;
    }
    
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
        
        console.log('[TA-cveicu] Theme applied:', theme);
    }
    
    // Function to fetch theme from settings
    function fetchAndApplyTheme() {
        var url = buildUrl(CONFIG.REST_ENDPOINT) + '?output_mode=json';
        
        $.ajax({
            url: url,
            type: 'GET',
            dataType: 'json',
            success: function(data) {
                var theme = 'light'; // default
                try {
                    if (data && data.entry && data.entry[0] && data.entry[0].content) {
                        theme = data.entry[0].content.theme || 'light';
                    }
                } catch (e) {
                    console.log('[TA-cveicu] Using default theme');
                }
                applyTheme(theme);
            },
            error: function(xhr, status, error) {
                console.warn('[TA-cveicu] Theme fetch failed:', status, error);
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
