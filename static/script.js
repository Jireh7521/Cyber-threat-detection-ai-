function predict() {
    const features = [
        parseFloat(document.getElementById("f1").value),
        parseFloat(document.getElementById("f2").value),
        parseFloat(document.getElementById("f3").value),
        parseFloat(document.getElementById("f4").value),
        parseFloat(document.getElementById("f5").value)
    ];

    fetch('/predict', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({features: features})
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("result").innerText = data.message;
    })
    .catch(err => {
        document.getElementById("result").innerText = "Error: " + err;
    });
}