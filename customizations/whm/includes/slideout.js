(function() {
    /**
     * A place for slideout references to live and play. It provides methods
     * to easily perform operations on all tabs/slideouts at once. It also
     * ensures that the slideout tabs are properly positioned and spaced.
     *
     * @class SlideoutList
     *
     */
    function SlideoutList() {
        this.slideouts = [];
        this.version = SlideoutList.version;
        this.isVisible = false;
    }

    SlideoutList.version = 1;
    SlideoutList.spaceBetweenTabs = 3;
    SlideoutList.bottomMargin = 35;

    /**
     * Hides the tab for all registered slideouts.
     */
    SlideoutList.prototype.hideAllTabs = function(activeSlideout) {
        this.slideouts.forEach(function(currentSlideout) {
            currentSlideout.hideTab();
        });

        if(this.legacyAnalyticsSlideout) {
            this.legacyAnalyticsSlideout.tab.hide();
        }
    };

    /**
     * Shows the expanded version of the tab for all registered slideouts.
     */
    SlideoutList.prototype.expandAllTabs = function() {
        this.slideouts.forEach(function(currentSlideout) {
            currentSlideout.showExpandedTab();
        });
    };

    /**
     * Shows the collapsed version of the tab for all registered slideouts.
     */
    SlideoutList.prototype.showAllTabs = function() {
        this.slideouts.forEach(function(currentSlideout) {
            currentSlideout.showCollapsedTab();
        });

        if(this.legacyAnalyticsSlideout) {
            this.legacyAnalyticsSlideout.tab.showCollapsed();
        }
    };

    /**
     * Adds items to the SlideoutList and performs a sort afterwards,
     * ensuring that the NPS tab is always on the tab.
     *
     * @param {slideout|slideout[]} slideout  One or more slideouts to add
     */
    SlideoutList.prototype.add = function(slideout) {
        if(Array.isArray(slideout)) {
            this.slideouts = this.slideouts.concat(slideout);
        }
        else {
            this.slideouts.push(slideout);
        }

        // Make sure NPS is always the first item shown
        this.slideouts.sort(function(a, b) {
            return a.id === "nps" ?
                -1 : b.id === "nps" ?
                    1 : 0;
        });

        this.positionAll();
    };

    /**
     * Sets style.bottom for all of the tabs. The NPS tab will always be on top.
     * If a legacy analytics tab is present, all tabs will be positioned in relation
     * to it. That tab is attached to its main content, so it's a little harder to
     * position that one properly, so this strategy avoids that problem.
     */
    SlideoutList.prototype.positionAll = function() {

        /**
         * Do not change positions if items are visible. This may result in
         * tabs not showing up on very slow connections, but for now this is
         * an acceptable compromise.
         */
        if(this.isVisible) {
            return;
        }

        var slideoutTabs = this.slideouts.map(function(slideout) {
            var tabInfo = _getTabMeasurements(slideout.tab);
            tabInfo.elem = slideout.tab;
            tabInfo.id = slideout.id;
            return tabInfo;
        });

        var legacyTab;
        if(this.legacyAnalyticsSlideout && this.legacyAnalyticsSlideout.tab) {
            legacyTab = _getTabMeasurements(this.legacyAnalyticsSlideout.tab.elem);
            legacyTab.elem = this.legacyAnalyticsSlideout.tab.elem;
            legacyTab.isLegacy = true;
            slideoutTabs.push(legacyTab); // Place legacy tabs at the end
        }

        for(var i = slideoutTabs.length - 1; i >= 0; i--) {
            var currentTab = slideoutTabs[i];
            var tabBelowCurrent = slideoutTabs[i + 1];

            /**
             * If a legacy tab exists, it will always be at the end of the
             * list and everything will be positioned around it.
             */
            if(currentTab.isLegacy) {
                // Move the legacy tab down ever so slightly for better aesthetics with the new tabs
                if(getComputedStyle(currentTab.elem).top === "30px") {
                    currentTab.elem.style.top = "35px";
                    currentTab.bottom -= 5;
                }
            }
            else if(!tabBelowCurrent) {
                // For the last tab, position based off the bottom margin
                currentTab.bottom = SlideoutList.bottomMargin;
                currentTab.elem.style.bottom = currentTab.bottom + "px";
            }
            else {
                // For all other tabs, position based off the tab below it
                currentTab.elem.style.bottom = (tabBelowCurrent.bottom + tabBelowCurrent.height + SlideoutList.spaceBetweenTabs) + "px";
            }
        }
    };

    function _getTabMeasurements(tabElem) {
        var tabRect = tabElem.getBoundingClientRect();
        return {
            height: tabRect.height,
            bottom: window.innerHeight - tabRect.bottom,
        };
    }

    /**
     * Stores a reference to the legacy Analytics slideout wrapper for later use
     * and bind listeners for open/close events on it.
     */
    SlideoutList.prototype.setLegacyAnalyticsSlideout = function() {
        var legacySlideout = this.legacyAnalyticsSlideout = CPANEL.legacyAnalyticsWrapper;

        if(legacySlideout) {
            // Open/close tabs in response to the legacy slideout
            legacySlideout.onOpen.subscribe(this.hideAllTabs.bind(this));
            legacySlideout.onClose.subscribe(this.showAllTabs.bind(this));
        }
    };

    /**
     * Initializes all slideouts.
     */
    SlideoutList.prototype.initializeAll = function() {
        this.slideouts.forEach(function(slideout) {
            slideout.animateEntrance();
        });
    };

    /**
     * Tries to initialize the legacy analytics wrapper and set the
     * position for the tabs on DOMContentLoaded.
     */
    SlideoutList.prototype.contentLoadedHandler = function() {
        this.setLegacyAnalyticsSlideout();
        this.positionAll();
    };

    /**
     * Adds listeners and sets a timer for the initial tab animations.
     */
    SlideoutList.prototype.activate = function() {

        var that = this;
        this.activatedItems = this.activatedItems || {};

        // Set initial tab positions on load
        if (document.readyState === "loading") {
            this.activatedItems.contentLoadedHandler = this.contentLoadedHandler.bind(this);
            document.addEventListener('DOMContentLoaded', this.activatedItems.contentLoadedHandler);
        }
        else {
            this.contentLoadedHandler();
        }

        // Reposition tabs on resize
        if(!this.activatedItems.debouncedPositionAll) {
            this.activatedItems.debouncedPositionAll = _debounce(this.positionAll, 100).bind(this);
            window.addEventListener("resize", this.activatedItems.debouncedPositionAll);
        }

        // Kick off the intro animations after a delay
        if(!this.activatedItems.initializeAllTimer) {
            this.activatedItems.initializeAllTimer = setTimeout(function() {
                that.isVisible = true;
                that.initializeAll();
            }, 2000);
        }
    };

    /**
     * Deactivates all listeners and the animation timer set by the activate method.
     */
    SlideoutList.prototype.deactivate = function() {

        if(this.activatedItems.contentLoadedHandler) {
            document.removeEventListener("DOMContentLoaded", this.activatedItem.contentLoadedHandler);
        }

        if(this.activatedItems.debouncedPositionAll) {
            window.removeEventListener("resize", this.activatedItems.debouncedPositionAll);
        }

        if(this.activatedItems.initializeAllTimer) {
            clearTimeout(this.activatedItems.initializeAllTimer);
        }

        delete this.activatedItems;
    };

    /**
     * Creates a new function that wraps a given function in a debouncer
     *
     * @param {function} func   The function to debounce
     * @param {number} delay    The debounce delay
     * @returns {function}   A new function that wraps the original in the debounce logic
     */
    function _debounce(func, delay) {
        var inDebounce;
        return function() {
            var context = this;
            var args = arguments;
            clearTimeout(inDebounce)
            inDebounce = setTimeout(function(){
                func.apply(context, args)
                }, delay);
        }
    }

    /**
     * Initializes a SlideoutList instance and attaches it to the CPANEL namespace.
     * If there is already an existing instance attached with an older implementation,
     * it will replace it.
     *
     * This method also kicks off the initialization routines for all slideouts.
     */
    function init() {
        var cp = window.CPANEL = window.CPANEL || {};
        if(!cp.slideoutList) {
            cp.slideoutList = new SlideoutList();
        }
        else if(cp.slideoutList && cp.slideoutList.version < SlideoutList.version) {
            var existingSlideouts = cp.slideoutList.slideouts;
            cp.slideoutList.deactivate();
            cp.slideoutList = new SlideoutList();
            SlideoutList.add(existingSlideouts);
        }

        cp.slideoutList.activate();
    }

    init();

})();

/**
 * @callback onOpenCallback
 * @description Called when the slideout opens.
 */

/**
 * @callback onCloseCallback
 * @description Called when the slideout closes.
 */

/**
 * @typedef {Object} SlideoutFactoryOptions
 * @property {HTMLElement} mainContainer   The main slideout container.
 * @property {HTMLElement} tab             The slideout tab.
 * @property {HTMLElement} closeButton     The close button within the slideout content container.
 * @property {string} id                   Some unique identification string to differentiate from other slideouts.
 * @property {string} sessionStorageKey    A unique key to place on sessionStorage that will be used to track the cPanel session ID.
 * @property {onOpenCallback} onOpen       A callback that will be run when the slideout opens.
 * @property {onCloseCallback} onClose     A callback that will be run when the slideout closes.
 */

/**
 * @typedef {Object} Slideout
 * @property {string} id                   Some unique identification string to differentiate from other slideouts.
 * @property {HTMLElement} mainContainer   The main slideout container.
 * @property {HTMLElement} tab             The slideout tab.
 * @property {function} openSlideOut       Opens the slideout.
 * @property {function} closeSlideOut      Closes the slideout.
 * @property {function} hideTab            Hides the slideout's tab.
 * @property {function} animateEntrance    Animates the first entrance of the slideout's tab.
 * @property {function} showCollapsedTab   Show the tab in its collapsed form.
 * @property {function} showExpandedTab    Show the tab in its expanded form.
 */

/**
 * Factory function that creates an instance of a Slideout. This instance
 * provide references to and can control the tab and main slideout display.
 *
 * @param {SlideoutFactoryOptions} options   An object of options to configure the slideout.
 * @returns {Slideout}
 */
window.slideoutFactory = function(options) {
    var html = document.querySelector("html");
    var whmSearchInput = document.getElementById("quickJump");
    var whmTopframeWrapper = document.getElementById("topFrameWrapper");

    // slideout specific variables
    var mainContainer = options.mainContainer;
    var tab = options.tab;
    var closeButton = options.closeButton;

    // Bail if we're missing elements. Don't throw so we don't break other slideouts
    if (!tab || !mainContainer || !closeButton) {
        return;
    }

    var slideout = {
        id: options.id,
        mainContainer: mainContainer,
        tab: tab,
        openSlideOut: openSlideOut,
        closeSlideOut: closeSlideOut,
        hideTab: hideTab,
        animateEntrance: animateEntrance,
        showCollapsedTab: showCollapsedTab,
        showExpandedTab: showExpandedTab,
    };
    window.CPANEL.slideoutList.add(slideout);

    // The tab and container elements are hidden by default, so make them visible.
    tab.classList.remove("hide");
    mainContainer.classList.remove("hide");

    /**
    * Expand the tab, wait for a predetermined time, and then collapse it.
    */
    function advertiseTab() {
        if(!tab && !mainContainer) {
            return;
        }

        tab.showExpanded();

        var animationCount = 0;
        var timedCollapse = function() {

            // Start the timer and remove the listener after both animations have finished.
            if(++animationCount >= 2) {
                setTimeout(function() {
                    if(!mainContainer.isActive()) {
                        tab.showCollapsed();
                    }
                }, 2500);
                tab.removeEventListener("animationend", timedCollapse);
            }
        };

        tab.addEventListener("animationend", timedCollapse);
    }

    /**
     * Animates the first entrance of the slideout's tab. Sometimes it will be
     * heavily animated (advertised) and sometimes it will be more subtle. This
     * is usually based on the cPanel session, as we don't want to barrage users
     * with animation on every page load and only want to show it upon their first
     * page load for the session.
     */
    function animateEntrance() {
        // The initial-state class ensures that there are no transition effects on first render.
        tab.classList.remove("initial-state");
        mainContainer.classList.remove("initial-state");

        if(canAdvertise()) {
            // set session state
            storeAdvertisedState();

            // Trigger the flashier animation
            advertiseTab();

        } else {
            // Trigger the subtle animation
            tab.showCollapsed();
        }
    }


    // Set up interactions that will persist
    if(mainContainer) {

        mainContainer.isActive = function() {
            return mainContainer.classList.contains("active");
        }

        // There is a listener at the document level that will close the slide-in on any
        // focus events, but we obviously don't want that to happen if they focus on anything
        // inside of the sidebar content area.
        mainContainer.addEventListener("focusin", function(e) {
            e.stopPropagation();
        });
    }

    if(closeButton) {
        closeButton.addEventListener("click", slideout.closeSlideOut);
    }

    if(tab) {
        tab.addEventListener("click", toggleSlideOut);
        tab.addEventListener("focus", function() {
            // Prevent the browser from shifting to show hidden contents when tabbing
            html.scrollLeft = 0;
            html.scrollRight = 0;
        });

        // Enable keyboard interactions with the tab
        tab.addEventListener("keyup", function(e) {
            if(
                normalizeKeyPress(e.key || e.keyCode) === " "
                || normalizeKeyPress(e.key || e.keyCode) === "Enter"
            ) {
                toggleSlideOut();
            }
        });

        /**
         * Shows the collapsed tab.
         */
        tab.showCollapsed = function() {
            tab.classList.add("tab-collapsed");
            tab.classList.remove("tab-hidden");
            tab.classList.remove("tab-expanded");
        };

        /**
         * Shows the expanded tab.
         */
        tab.showExpanded = function() {
            tab.classList.add("tab-expanded");
            tab.classList.remove("tab-hidden");
            tab.classList.remove("tab-collapsed");
        };

        /**
         * Hides the tab.
         */
        tab.hide = function() {
            tab.blur();
            tab.classList.add("tab-hidden");
            tab.classList.remove("tab-expanded");
            tab.classList.remove("tab-collapsed");
        };
    }

    /**
     * Shows the collapsed version of the tab.
     */
    function showCollapsedTab() {
        tab && tab.showCollapsed();
    }

    /**
     * Shows the expanded version of the tab.
     */
    function showExpandedTab() {
        tab && tab.showExpanded();
    }

    var debouncedRepositionSlideout = debounce(repositionSlideout, 100);

    /**
     * Calculates and sets the correct height for the slideout based on the
     * height of the WHM top bar.
     */
    function repositionSlideout() {
        if(whmTopframeWrapper){
            var height = whmTopframeWrapper.offsetHeight;
            var spacer = 1; // To introduce additional gap between top frame and slideout
            if(mainContainer){
                mainContainer.style.top = (height + spacer) + "px";
            }
        }
    }

    // Set up interactions that are added when the slide-out is open and
    // removed when it is closed
    var handlers = {
        /**
         * Closes the slideout upon certain key presses.
         */
        documentKeyup: function(e) {
            var key = normalizeKeyPress(e.key || e.keyCode);

            // Close the slide-out on ESC and WHM hotkeys
            if(mainContainer && mainContainer.isActive()) {
                if(
                    key === "Escape"
                    || key === "F2" && e.altKey
                    || key === "`"
                    || key === "/" && e.ctrlKey
                    || key === "/" && e.metaKey
                    || key === "*" && e.shiftKey
                ) {
                    slideout.closeSlideOut();
                }
            }
        },

        /**
         * Closes the slideout when the WHM search bar is focused.
         */
        whmSearchFocus: function() {
            if(mainContainer.isActive()) {
                slideout.closeSlideOut();
            }
        },

        /**
         * Recalculates WHM's top frame after a viewport resize.
         */
        windowResize: function() {
            debouncedRepositionSlideout();
        },

    };

    /**
     * Determines whether or not we should advertise the slideout tab or if it
     * should perform the more subdued intro animation.
     */
    function canAdvertise() {
        if (typeof(Storage) !== "undefined") {
            var cpSessionId = getCpanelSessionId();
            if(window.sessionStorage &&
                cpSessionId !== sessionStorage[options.sessionStorageKey]){
                return true;
            }
        }
        return false;
    }


    /**
     * Retrieves the cPanel-provided session ID.
     */
    function getCpanelSessionId() {
        if(window &&
            window.COMMON &&
            window.COMMON.securityToken){
                return window.COMMON.securityToken;
        }
        return null;
    }

    /**
     * Stores the cPanel-provided session ID into the browser's sessionStorage so
     * we can determine whether or not the slideout has already been advertised for
     * a given cPanel session.
     */
    function storeAdvertisedState() {
        if (typeof(Storage) !== "undefined") {
            // Incase session storage is not supported or is full
            try{
                sessionStorage[options.sessionStorageKey] = getCpanelSessionId();
            }catch(err){
                // Do nothing with exception
            }
        }
    }

    /**
     * Attaches listeners for events that represent the user attempting to
     * interact with WHM and trying to get out of the slideout. These are
     * only necessary when the slideout is open.
     */
    function attachListeners() {
        if(whmSearchInput) {
            whmSearchInput.addEventListener("focus", handlers.whmSearchFocus);
        }

        document.addEventListener("keyup", handlers.documentKeyup);
        document.addEventListener("focusin", handlers.documentFocus); // focusin bubbles

        // reposition slideout when document resizes
        window.addEventListener("resize", handlers.windowResize);
    }

    /**
     * Detaches listeners for events that represent the user attempting to
     * interact with WHM and trying to get out of the slide-out. These are
     * only necessary when the slideout is open.
     */
    function detachListeners() {
        if(whmSearchInput) {
            whmSearchInput.removeEventListener("focus", handlers.whmSearchFocus);
        }

        document.removeEventListener("keyup", handlers.documentKeyup);
        document.removeEventListener("focusin", handlers.documentFocus); // focusin bubbles
        window.removeEventListener("resize", handlers.windowResize);
    }

    var keyCodeMap = {
        13: "Enter",
        27: "Escape",
        32: " ", // Space
        56: "*",
        113: "F2",
        191: "/",
        192: "`",
    };

    /**
     * Accepts either a key (string) or keyCode (number) value from a KeyboardEvent object
     * and returns the corresponding key value. The keyCode property is deprecated, but offers
     * broader browser support, so we use it as a fallback while still using the simpler and
     * more future-proof KeyboardEvent.key strings in the code.
     *
     * @param {KeyboardEvent.key|KeyboardEvent.keyCode} keyCode   The value to normalize to a key value
     * @returns KeyboardEvent.key
     */
    function normalizeKeyPress(keyCode) {
        return (typeof keyCode === "number") ? keyCodeMap[keyCode] : keyCode;
    }

    /**
     * Opens the slideout and hides all slideout tabs. If an onOpen
     * callback was passed to the factory, it will be called here.
     */
    function openSlideOut() {
        mainContainer && mainContainer.classList.add("active");
        if(tab) {
            tab.hide();
            tab.setAttribute("aria-expanded", true);
        }


        // Set the position of the slideout based on whm top frame
        repositionSlideout();
        attachListeners();

        window.CPANEL.slideoutList.hideAllTabs();

        if(options.onOpen){
            options.onOpen();
        }
    }

    /**
     * Closes the slideout and shows all slideout tabs. If an onClose
     * callback was passed to the factory, it will be called here.
     */
    function closeSlideOut() {
        mainContainer && mainContainer.classList.remove("active");
        if(tab) {
            tab.showCollapsed();
            tab.setAttribute("aria-expanded", false);
        }
        detachListeners();

        window.CPANEL.slideoutList.showAllTabs();

        if(options.onClose){
            options.onClose();
        }
    }

    /**
     * Toggles the slideout, depending on its current state.
     */
    function toggleSlideOut() {
        if(mainContainer && mainContainer.isActive()) {
            slideout.closeSlideOut();
        }
        else {
            slideout.openSlideOut();
        }
    }

    /**
     * Hides the tab associated with this slideout.
     */
    function hideTab() {
        if(tab) {
            tab.hide();
        }
    }

    /**
     * Creates a new function that wraps a given function in a debouncer
     *
     * @param {function} func   The function to debounce
     * @param {number} delay    The debounce delay
     * @returns {function}   A new function that wraps the original in the debounce logic
     */
    function debounce(func, delay) {
        var inDebounce;
        return function() {
            var context = this;
            var args = arguments;
            clearTimeout(inDebounce)
            inDebounce = setTimeout(function(){
                func.apply(context, args)
                }, delay);
        }
    }

    return slideout;
}