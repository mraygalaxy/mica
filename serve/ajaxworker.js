function go_success(response) {
    var result = {};
    result.success = true;
    result.response = response;
    self.postMessage(result);
}

function go_fail(XMLHttpRequest, ajaxOptions, thrownError) {
    console.log("Failure: " + XMLHttpRequest.status + ": " + XMLHttpRequest.responseText + ": " + thrownError);
    var result = {};
    result.success = false;
    result.statusCode = XMLHttpRequest.status;
    result.responseText = XMLHttpRequest.responseText;
    //result.ajaxOptions = ajaxOptions;
    result.thrownError = thrownError;
    self.postMessage(result);
}
self.onmessage = function(e) {
    var params = e.data;

    dest = params.prefix + '/api?human=' + params.human + '&alien=' + params.target;
    if (params.form) {
        $.ajax({
                url: dest,
                type: "POST",
                data: params.formData,
                success: go_success,
                error: go_fail
        });
    } else {
        $.ajax({
                url: dest, //2415
                type: "GET", 
                dataType: "html",
                success: go_success,
                error: go_fail
        });
    }
};
