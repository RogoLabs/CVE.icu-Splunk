/**
 * CVE.ICU Setup Page Controller
 * World-class setup experience with real-time theme preview
 * 
 * Theme is stored in localStorage for instant, reliable persistence
 * across all dashboards without REST API complexity.
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    'use strict';
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    var CONFIG = {
        APP_NAME: 'TA-cveicu',
        STORAGE_KEY: 'cveicu_theme',
        REST_ENDPOINT: '/servicesNS/nobody/TA-cveicu/ta_cveicu/ta_cveicu_settings/github_settings',
        DASHBOARD_URL: '/app/TA-cveicu/cve_dashboard_instant',
        REDIRECT_DELAY: 600
    };
    
    // ========================================================================
    // THEME MANAGEMENT
    // ========================================================================
    
    /**
     * Get saved theme from localStorage
     */
    function getSavedTheme() {
        try {
            return localStorage.getItem(CONFIG.STORAGE_KEY) || 'light';
        } catch (e) {
            return 'light';
        }
    }
    
    /**
     * Save theme to localStorage
     */
    function saveTheme(theme) {
        try {
            localStorage.setItem(CONFIG.STORAGE_KEY, theme);
            console.log('[CVE.ICU] Theme saved:', theme);
            return true;
        } catch (e) {
            console.error('[CVE.ICU] Failed to save theme:', e);
            return false;
        }
    }
    
    /**
     * Apply theme to the page immediately
     */
    function applyTheme(theme) {
        var isDark = (theme === 'dark');
        
        // Apply to multiple elements for maximum compatibility
        $('html').toggleClass('dark', isDark);
        $('body').toggleClass('dark', isDark);
        $('.dashboard-body').toggleClass('dark', isDark);
        $('.setup-container').attr('data-theme', theme);
        
        // Update Splunk chrome if possible
        $('.shared-page-chrome').toggleClass('dark', isDark);
        $('[data-view="views/shared/splunkbar/Master"]').toggleClass('dark', isDark);
        
        console.log('[CVE.ICU] Theme applied:', theme);
    }
    
    /**
     * Setup live theme preview
     */
    function setupThemeToggle() {
        $('input[name="theme"]').on('change', function() {
            var theme = $(this).val();
            applyTheme(theme);
            // Save immediately so it persists even if they navigate away
            saveTheme(theme);
        });
    }
    
    // ========================================================================
    // URL HELPERS
    // ========================================================================
    
    function getLocale() {
        var match = window.location.pathname.match(/^\/([a-z]{2}-[A-Z]{2})\//);
        return match ? match[1] : 'en-US';
    }
    
    function buildUrl(path) {
        return '/' + getLocale() + path;
    }
    
    function getFormKey() {
        if (window.$C && window.$C.FORM_KEY) {
            return window.$C.FORM_KEY;
        }
        var match = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        return match ? match[1] : '';
    }
    
    // ========================================================================
    // UI HELPERS
    // ========================================================================
    
    function showStatus(type, message, icon) {
        var $status = $('#setup-status');
        var iconHtml = icon ? '<span class="status-icon">' + icon + '</span> ' : '';
        $status
            .removeClass('loading success error')
            .addClass(type)
            .html(iconHtml + message)
            .fadeIn(200);
    }
    
    function setButtonState(disabled, text) {
        var $btn = $('#launch-btn');
        var $btnText = $btn.find('.btn-text');
        var $btnSpinner = $btn.find('.btn-spinner');
        
        $btn.prop('disabled', disabled);
        
        if (disabled) {
            $btnText.text(text || 'Processing...');
            $btnSpinner.show();
        } else {
            $btnText.text('Launch Dashboard');
            $btnSpinner.hide();
        }
    }
    
    // ========================================================================
    // SETUP COMPLETION
    // ========================================================================
    
    function completeSetup() {
        var theme = $('input[name="theme"]:checked').val() || 'light';
        
        // Save theme to localStorage (primary storage)
        saveTheme(theme);
        
        // Update UI
        showStatus('loading', 'Configuring CVE.ICU...', '⚙️');
        setButtonState(true, 'Setting up...');
        
        // Call REST endpoint to mark app as configured
        var restUrl = buildUrl('/splunkd/__raw' + CONFIG.REST_ENDPOINT);
        
        $.ajax({
            url: restUrl,
            type: 'POST',
            data: {
                github_token: '',
                theme: theme
            },
            headers: {
                'X-Splunk-Form-Key': getFormKey(),
                'X-Requested-With': 'XMLHttpRequest'
            },
            timeout: 10000
        })
        .always(function() {
            // Always redirect - localStorage theme will work regardless
            showStatus('success', 'Setup complete! Launching dashboard...', '✅');
            setButtonState(true, 'Redirecting...');
            
            setTimeout(function() {
                window.location.href = buildUrl(CONFIG.DASHBOARD_URL);
            }, CONFIG.REDIRECT_DELAY);
        });
    }
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    function init() {
        console.log('[CVE.ICU] Initializing setup page...');
        
        // Load saved theme and apply it
        var savedTheme = getSavedTheme();
        applyTheme(savedTheme);
        
        // Pre-select the saved theme radio
        $('input[name="theme"][value="' + savedTheme + '"]').prop('checked', true);
        
        // Setup live theme toggle
        setupThemeToggle();
        
        // Setup launch button
        $('#launch-btn')
            .removeAttr('onclick')
            .on('click', function(e) {
                e.preventDefault();
                if (!$(this).prop('disabled')) {
                    completeSetup();
                }
            });
        
        // Keyboard shortcut: Enter to launch
        $(document).on('keypress', function(e) {
            if (e.which === 13 && !$('#launch-btn').prop('disabled')) {
                completeSetup();
            }
        });
        
        console.log('[CVE.ICU] Setup page ready. Saved theme:', savedTheme);
    }
    
    // Start when DOM is ready
    $(document).ready(init);
});
