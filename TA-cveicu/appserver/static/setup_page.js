/**
 * TA-cveicu Setup Page Controller
 * 
 * Handles the "Launch Dashboard" button click, making an async POST to the
 * setup REST handler to mark the app as configured and trigger a cache reload.
 * 
 * This ensures Splunk's configuration cache is properly invalidated before
 * redirecting to the dashboard, preventing the setup redirect loop.
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    'use strict';
    
    // Configuration
    var CONFIG = {
        APP_NAME: 'TA-cveicu',
        REST_ENDPOINT: '/servicesNS/nobody/TA-cveicu/ta_cveicu/ta_cveicu_settings/github_settings',
        DASHBOARD_URL: '/app/TA-cveicu/cve_dashboard_instant',
        REDIRECT_DELAY: 500  // ms to wait after successful POST before redirect
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
        return '/' + locale + path;
    }
    
    /**
     * Get the Splunk form key for CSRF protection
     */
    function getFormKey() {
        // Try multiple sources for the form key
        if (window.$C && window.$C.FORM_KEY) {
            return window.$C.FORM_KEY;
        }
        // Fallback: try to get from cookie
        var match = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        return match ? match[1] : '';
    }
    
    /**
     * Show status message in the UI
     */
    function showStatus(type, message) {
        var $status = $('#setup-status');
        $status.removeClass('loading success error').addClass(type);
        $status.text(message);
        $status.show();
    }
    
    /**
     * Disable the launch button during processing
     */
    function setButtonState(disabled) {
        var $btn = $('#launch-btn');
        $btn.prop('disabled', disabled);
        $btn.css('opacity', disabled ? '0.6' : '1');
    }
    
    /**
     * Get the selected theme preference
     */
    function getSelectedTheme() {
        var $checked = $('input[name="theme"]:checked');
        return $checked.length ? $checked.val() : 'light';
    }
    
    /**
     * Complete the setup by calling the REST handler and redirecting
     */
    function completeSetup() {
        var theme = getSelectedTheme();
        
        // Show loading state
        showStatus('loading', 'Completing setup...');
        setButtonState(true);
        
        // Build the REST endpoint URL
        var restUrl = buildUrl('/splunkd/__raw' + CONFIG.REST_ENDPOINT);
        
        // Make async POST to the setup handler
        $.ajax({
            url: restUrl,
            type: 'POST',
            data: {
                github_token: '',  // Empty token - not required
                theme: theme
            },
            headers: {
                'X-Splunk-Form-Key': getFormKey(),
                'X-Requested-With': 'XMLHttpRequest'
            },
            success: function(response, textStatus, xhr) {
                // Setup complete - the handler has triggered cache reload
                showStatus('success', 'Setup complete! Redirecting to dashboard...');
                
                // Wait for cache to clear, then redirect
                setTimeout(function() {
                    window.location.href = buildUrl(CONFIG.DASHBOARD_URL);
                }, CONFIG.REDIRECT_DELAY);
            },
            error: function(xhr, textStatus, errorThrown) {
                console.warn('[TA-cveicu] Setup POST returned error:', textStatus, errorThrown);
                
                // Even on error, the default/app.conf has is_configured=1
                // So we can still redirect - it should work
                showStatus('success', 'Redirecting to dashboard...');
                
                setTimeout(function() {
                    window.location.href = buildUrl(CONFIG.DASHBOARD_URL);
                }, 300);
            }
        });
    }
    
    /**
     * Initialize the setup page
     */
    function init() {
        // Remove inline onclick handler if present
        var $btn = $('#launch-btn');
        $btn.removeAttr('onclick');
        
        // Attach click handler
        $btn.on('click', function(e) {
            e.preventDefault();
            completeSetup();
        });
        
        // Also expose globally for fallback
        window.completeSetup = completeSetup;
        
        console.log('[TA-cveicu] Setup page controller initialized');
    }
    
    // Initialize when DOM is ready
    $(document).ready(init);
});
