// supertabs.js
require([
  'jquery',
  'underscore',
  'splunkjs/mvc',
  'bootstrap.tab',
  'splunkjs/mvc/simplexml/ready!',
], function ($, _, mvc) {
  var tabsInitialized = [];

  /**
   * Force a re-render of the panels within the given element ID (row).
   */
  var rerenderPanels = function (elementId, force) {
    if (typeof force === 'undefined') {
      force = true;
    }
    if (!force && _.contains(tabsInitialized, elementId)) {
      return;
    }

    var elements = $('#' + elementId + ' .dashboard-element');
    for (var d = 0; d < elements.length; d++) {
      var component = mvc.Components.get(elements[d].id);
      if (component && typeof component.render === 'function') {
        if ($('#' + elements[d].id).is(':visible')) {
          component.render();
        }
      }
    }
    if (!_.contains(tabsInitialized, elementId)) {
      tabsInitialized.push(elementId);
    }
  };

  /**
   * Hides all rows that are managed by the tabbing system.
   */
  function hideAllManagedContentRows() {
    // Hide main tab content
    $('#tab_objective').hide();
    $('#tab_next').hide();
    
    // Hide all regional header rows
    $('#tab_global_header_row').hide();
    $('#tab_amer_header_row').hide();
    $('#tab_emea_header_row').hide();
    $('#tab_apjc_header_row').hide();
    $('#tab_anz_header_row').hide();
    
    // Hide all Global step content rows
    $('#global_step1_content_row').hide();
    $('#global_step2_intro_row').hide();
    $('#global_step2_search_panel_row').hide();
    $('#global_step2_table_row').hide();
    $('#global_step3_content_row').hide();
    $('#global_step4_content_row').hide();
    
    // Hide all AMER step content rows
    $('#amer_step1_content_row').hide();
    $('#amer_step2_intro_row').hide();
    $('#amer_step2_search_panel_row').hide();
    $('#amer_step2_table_row').hide();
    $('#amer_step3_content_row').hide();
    $('#amer_step4_content_row').hide();
    
    // Hide all EMEA step content rows
    $('#emea_step1_content_row').hide();
    $('#emea_step2_intro_row').hide();
    $('#emea_step2_search_panel_row').hide();
    $('#emea_step2_table_row').hide();
    $('#emea_step3_content_row').hide();
    $('#emea_step4_content_row').hide();
    
    // Hide all APJC step content rows
    $('#apjc_step1_content_row').hide();
    $('#apjc_step2_intro_row').hide();
    $('#apjc_step2_search_panel_row').hide();
    $('#apjc_step2_table_row').hide();
    $('#apjc_step3_content_row').hide();
    $('#apjc_step4_content_row').hide();
    
    // Hide all ANZ step content rows
    $('#anz_step1_content_row').hide();
    $('#anz_step2_intro_row').hide();
    $('#anz_step2_search_panel_row').hide();
    $('#anz_step2_table_row').hide();
    $('#anz_step3_content_row').hide();
    $('#anz_step4_content_row').hide();
  }

  /**
   * Handles the selection of a main tab.
   */
  function handleMainTabClick(e, isInitialLoad) {
    var $clickedTabLink;
    if (e && e.target) {
      e.preventDefault();
      $clickedTabLink = $(e.target).closest('a.toggle-tab');
    } else {
      $clickedTabLink = $(e);
    }
    
    if (!$clickedTabLink || !$clickedTabLink.length) {
      return;
    }

    var $tabLi = $clickedTabLink.closest('li');
    var $mainTabNav = $('ul#main_tabs_nav');

    // Update visual state
    $mainTabNav.find('li.active').removeClass('active');
    $tabLi.addClass('active');

    // CRITICAL: Hide all managed content first
    hideAllManagedContentRows();

    // Show content rows specified in the main tab's data-elements
    var mainTabElementsToShow = $clickedTabLink.data('elements');
    if (mainTabElementsToShow) {
      var elementsArray = mainTabElementsToShow.split(',');
      elementsArray.forEach(function (paneId) {
        var $pane = $('#' + paneId.trim());
        $pane.show();
        rerenderPanels(paneId.trim(), !isInitialLoad);
      });

      // Handle regional tabs (those with header rows)
      var isRegionalTab = elementsArray.some(id => id.includes("_header_row"));
      if (isRegionalTab) {
        var regionHeaderRowId = elementsArray.find(id => id.includes("_header_row"));
        if (regionHeaderRowId) {
          var $subTabNav = $('#' + regionHeaderRowId.trim()).find('ul.nav-tabs[id*="_steps_tabs"]');
          if ($subTabNav.length) {
            // Activate the first sub-tab
            $subTabNav.find('li.active').removeClass('active');
            var $firstSubTabLi = $subTabNav.find('li:first-child');
            $firstSubTabLi.addClass('active');
            
            // Show content for the first sub-tab if not already shown
            var $firstSubTabLink = $firstSubTabLi.find('a.toggle-tab');
            if ($firstSubTabLink.data('elements')) {
              var firstSubTabElements = $firstSubTabLink.data('elements').split(',');
              firstSubTabElements.forEach(function(subPaneId) {
                var $subPane = $('#' + subPaneId.trim());
                if (!$subPane.is(':visible')) {
                  $subPane.show();
                }
                rerenderPanels(subPaneId.trim(), !isInitialLoad);
              });
            }
          }
        }
      }
    }
    setActiveTabToken($clickedTabLink);
  }

  /**
   * Handles the selection of a sub-tab (step tab).
   */
  function handleSubTabClick(e) {
    e.preventDefault();
    var $clickedSubTabLink = $(e.target).closest('a.toggle-tab');
    if (!$clickedSubTabLink.length) return;

    var $subTabLi = $clickedSubTabLink.closest('li');
    var $subTabNav = $clickedSubTabLink.closest('ul.nav-tabs');
    var regionPrefix = $subTabNav.attr('id').split('_')[0]; // e.g., "global"

    // Update visual state for this sub-tab navigation
    $subTabNav.find('li.active').removeClass('active');
    $subTabLi.addClass('active');

    // Hide all step content rows for THIS REGION ONLY
    $('#' + regionPrefix + '_step1_content_row').hide();
    $('#' + regionPrefix + '_step2_intro_row').hide();
    $('#' + regionPrefix + '_step2_search_panel_row').hide();
    $('#' + regionPrefix + '_step2_table_row').hide();
    $('#' + regionPrefix + '_step3_content_row').hide();
    $('#' + regionPrefix + '_step4_content_row').hide();

    // Show content for the clicked sub-tab
    var subTabElementsToShow = $clickedSubTabLink.data('elements');
    if (subTabElementsToShow) {
      subTabElementsToShow.split(',').forEach(function (paneId) {
        var $pane = $('#' + paneId.trim());
        $pane.show();
        rerenderPanels(paneId.trim(), true);
      });
    }
  }

  var setActiveTabToken = function ($activeTabLink) {
    var tokens = mvc.Components.getInstance('submitted');
    if (!tokens) return;

    // Clear all main tab tokens first
    $('ul#main_tabs_nav a.toggle-tab').each(function() {
      var tokenString = $(this).data('token');
      if (tokenString) {
        tokenString.split(',').forEach(function(token) {
          if (tokens.get(token.trim()) !== undefined) {
            tokens.set(token.trim(), undefined);
          }
        });
      }
    });

    var activeTabTokenString = $activeTabLink.data('token');
    if (activeTabTokenString) {
      activeTabTokenString.split(',').forEach(function (token) {
        tokens.set(token.trim(), 'true');
      });
    }
  };

  /**
   * Perform the initial setup for making the tabs work.
   */
  var firstTimeTabSetup = function () {
    // Bind click events
    $(document.body).on('click', 'ul#main_tabs_nav a.toggle-tab', function(e){
      handleMainTabClick(e, false);
    });

    $(document.body).on('click', 'ul[id*="_steps_tabs"] a.toggle-tab', function(e){
      handleSubTabClick(e);
    });

    // Initial comprehensive hide
    hideAllManagedContentRows();

    // Determine and activate the initially active main tab
    var $activeMainTabLink = $('ul#main_tabs_nav li.active > a.toggle-tab').first();
    if (!$activeMainTabLink.length) {
      $activeMainTabLink = $('ul#main_tabs_nav li:first-child > a.toggle-tab').first();
      if ($activeMainTabLink.length) {
        $('ul#main_tabs_nav li').removeClass('active');
        $activeMainTabLink.closest('li').addClass('active');
      }
    }

    if ($activeMainTabLink.length) {
      handleMainTabClick($activeMainTabLink.get(0), true);
    }

    var submit = mvc.Components.get('submit');
    if (submit) {
      submit.on('submit', function () {
        // Token clearing logic on submit if needed
      });
    }
  };

  firstTimeTabSetup();
});