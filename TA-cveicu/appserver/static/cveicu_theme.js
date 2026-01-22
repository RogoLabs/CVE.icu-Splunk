/**
 * CVE.ICU Theme Manager
 * 
 * Applies saved theme from localStorage to all CVE.ICU dashboards.
 * This script runs on every dashboard page load to ensure consistent theming.
 * 
 * Theme storage: localStorage key 'cveicu_theme' = 'light' | 'dark'
 */

(function() {
    'use strict';
    
    var STORAGE_KEY = 'cveicu_theme';
    
    /**
     * Get theme from localStorage
     */
    function getTheme() {
        try {
            return localStorage.getItem(STORAGE_KEY) || 'light';
        } catch (e) {
            return 'light';
        }
    }
    
    /**
     * Apply theme immediately (before page fully loads to prevent flash)
     */
    function applyThemeEarly(theme) {
        var isDark = (theme === 'dark');
        
        // Apply to html/body immediately
        if (isDark) {
            document.documentElement.classList.add('dark');
            document.body && document.body.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
            document.body && document.body.classList.remove('dark');
        }
    }
    
    /**
     * Apply theme after Splunk loads (for dashboard elements)
     */
    function applyThemeFull(theme) {
        var isDark = (theme === 'dark');
        
        // Dashboard body
        var dashBody = document.querySelector('.dashboard-body');
        if (dashBody) {
            dashBody.classList.toggle('dark', isDark);
        }
        
        // Splunk bar
        var splunkBar = document.querySelector('[data-view="views/shared/splunkbar/Master"]');
        if (splunkBar) {
            splunkBar.classList.toggle('dark', isDark);
        }
        
        // Shared chrome
        var chrome = document.querySelector('.shared-page-chrome');
        if (chrome) {
            chrome.classList.toggle('dark', isDark);
        }
        
        console.log('[CVE.ICU] Theme fully applied:', theme);
    }
    
    // Apply early (prevents flash of wrong theme)
    var theme = getTheme();
    applyThemeEarly(theme);
    
    // Apply full theme after DOM loads
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            applyThemeFull(theme);
        });
    } else {
        applyThemeFull(theme);
    }
    
    // Also apply after Splunk's async loading completes
    if (typeof require !== 'undefined') {
        require(['jquery', 'splunkjs/mvc/simplexml/ready!'], function($) {
            applyThemeFull(theme);
            
            // Re-apply after a short delay to catch late-loading elements
            setTimeout(function() {
                applyThemeFull(theme);
            }, 500);
        });
    }
})();
