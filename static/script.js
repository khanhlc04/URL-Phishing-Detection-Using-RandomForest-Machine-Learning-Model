function checkURL() {
    let url = document.getElementById("urlInput").value;
    let resultElement = document.getElementById("result");
    let explanationElement = document.getElementById("explanation");

    if (!url) {
        resultElement.innerHTML = "Vui lòng nhập URL.";
        explanationElement.innerHTML = "";
        return;
    }

    // Hiển thị trạng thái kiểm tra
    resultElement.innerHTML = "Đang kiểm tra... <span class='loading'></span>";
    explanationElement.innerHTML = "";

    fetch("/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            resultElement.innerHTML = "Lỗi: " + data.error;
            explanationElement.innerHTML = "";
        } else {
            let color = data.prediction === "Phishing" ? "red" : "green";
            let viPrediction = data.prediction === "Phishing" ? "Lừa đảo" : "An toàn";
            resultElement.innerHTML = `<strong>Kết quả:</strong> <span style=\"color: ${color}\">${viPrediction}</span>`;

            let explanationText = data.reasons ? data.reasons.map(reason => `• ${reason}`).join("<br>") : "Không có giải thích.";
            explanationElement.innerHTML = `<strong>Giải thích:</strong><br>${explanationText}`;
        }
    })
    .catch(error => {
        resultElement.innerHTML = "Có lỗi khi kiểm tra URL.";
        explanationElement.innerHTML = "";
        console.error("Lỗi:", error);
    });
}
