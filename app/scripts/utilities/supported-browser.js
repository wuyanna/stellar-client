var ROBOTS = /GoogleBot|Bingbot|YandexBot|Baiduspider/i;

/* exported isSupportedBrowser */
function isSupportedBrowser() {
  // whitelist robots so they can scrape the login page
  if(ROBOTS.test(navigator.userAgent))                { return true; }

  
  if(typeof Float64Array === "undefined")             { alert("Float64Array not supported"); return false; }
  
  if(!Modernizr.websockets)                           { alert("Modernizr.websockets not enabled"); return false; }
  
  if(!Modernizr.dataview)                             { alert("Modernizr.dataview not enabled"); return false; }

  // HACK: A specific version of Android's stock browser (AppleWebKit/534.30)
  // has a broken implementation of WebSocket. This can be removed if Modernizr
  // fixes the issue (https://github.com/Modernizr/Modernizr/issues/1399).
  if(navigator.userAgent.match('AppleWebKit/534.30')) { alert("AppleWebKit not supported"); return false; }


  // Getting tons of sce errors from this 11 year old browser
  if(navigator.userAgent.match('Opera 7.23')) { alert("Opera not supported"); return false; }

  return true;
}