(() => {
  "use strict";
  let controlLoaded = false;
  let blockedRejected = false;
  let failed = false;

  const finish = () => {
    if (failed) {
      document.title = "ZSEC DNR FAIL";
    } else if (controlLoaded && blockedRejected) {
      document.title = "ZSEC DNR PASS";
    }
  };
  const load = (source, onLoad, onError) => {
    const script = document.createElement("script");
    script.src = source;
    script.onload = onLoad;
    script.onerror = onError;
    document.head.appendChild(script);
  };

  load("control.js", () => {
    controlLoaded = window.zsecRuntimeControlLoaded === true;
    if (!controlLoaded) failed = true;
    finish();
  }, () => {
    failed = true;
    finish();
  });
  load("blocked.js", () => {
    failed = true;
    finish();
  }, () => {
    blockedRejected = true;
    finish();
  });
  window.setTimeout(() => {
    if (!controlLoaded || !blockedRejected) failed = true;
    finish();
  }, 5000);
})();
