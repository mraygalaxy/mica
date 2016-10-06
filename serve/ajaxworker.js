function go_success(response) {
    var result = {};
    result.success = true;
    result.response = response;
    self.postMessage(result);
}

function go_fail(XMLHttpRequest, ajaxOptions, thrownError) {
    var result = {};
    result.success = false;
    result.response = response;
    result.XMLHttpRequest = XMLHttpRequest;
    result.ajaxOptions = ajaxOptions;
    result.thrownError = thrownError;
    self.postMessage(result);
}
self.onmessage = function(e) {
    var params = e.data;

    if (params.form) {
        $.ajax({
                type: "POST",
                url: params.prefix + '/api?human=' + params.human + '&alien=' + params.target,
                data: params.formData,
                success: go_success,
                error: go_fail
        });
    } else {
        $.ajax({
                url: params.prefix + '/api?human=' + params.human + '&alien=' + params.target,
                type: "GET", 
                dataType: "html",
                success: go_success,
                error: go_fail
        });
    }
};
