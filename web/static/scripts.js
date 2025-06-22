document.addEventListener("DOMContentLoaded", function () {  // Esperamos a que se cargue la página al completo
    let chatContainer = document.getElementById("chat-bot"); // Creamos la variable del chat
    chatContainer.innerHTML = ""; // Limpiamos el chat
    let mensaje = document.createElement("div"); // Creamos un mensaje como div

    mensaje.classList.add("mensaje_bot"); // Le damos la clase mensaje_bot

    mensaje.innerHTML = `<div id= "mensaje_bot" class="row mb-2 ">
                <div class="col-1 p-0">
                    <i class="bi bi-robot"></i>
                </div>
                <div class="col-11 rounded-3 bg-secondary p-2 d-flex align-items-center m-0 text-white">
                    <p class="m-2">Hola, ¡Bienvenido al chat de SVAIA! </p>
                </div>
            </div>`;       

    chatContainer.appendChild(mensaje);
});
document.getElementById("send-button").addEventListener("click", sendMessage);  // Detecta si le da al botón "enviar"
document.getElementById("message-input").addEventListener("keypress", function(event) {  // Detecta si el usuario presiona "Enter"
    if (event.key === "Enter") {
        sendMessage();
    }
});

function sendMessage() {
    let input = document.getElementById("message-input");  
    let message = input.value.trim();  

    if (message !== "") {  
        let chatbot = document.getElementById("chat-bot");  

        // Mostrar mensaje del usuario
        let message_usuario_div = document.createElement("div");
        message_usuario_div.classList.add("mensaje_usuario");
        message_usuario_div.innerHTML = `
            <div id="mensaje_usuario" class="row my-2">
                <div class="col-11 rounded-3 bg-primary p-2 d-flex align-items-center m-0 text-white">
                    <p class="m-2">${message}</p>
                </div>
                <div class="col-1 d-flex justify-content-end p-0">
                    <i class="bi bi-person-fill"></i>
                </div>
            </div>`;

        chatbot.appendChild(message_usuario_div); 

        // Obtener el token del localStorage
        const token = localStorage.getItem('access_token');
        if (!token) {
            console.error("No hay token de acceso");
            return;
        }

        // Realizar la petición al chat
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "http://localhost:5002/api/chat", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.setRequestHeader("Authorization", `Bearer ${token}`);

        xhr.onload = function() {
            if (xhr.status === 401) {
                // Token expirado o inválido
                console.error("Token expirado o inválido");
                window.location.href = '/login';  // Redirigir al login
                return;
            }
            
            if (xhr.status >= 200 && xhr.status < 300) {
                var data = JSON.parse(xhr.responseText);  

                var message_bot_div = document.createElement("div");
                message_bot_div.classList.add("mensaje_bot");
                message_bot_div.innerHTML = `
                    <div class="row mb-2">
                        <div class="col-1 p-0">
                            <i class="bi bi-robot"></i>
                        </div>
                        <div class="col-11 rounded-3 bg-secondary p-2 d-flex align-items-center m-0 text-white">
                            <p class="m-2">${data.respuesta}</p>
                        </div>
                    </div>`;
                
                chatbot.appendChild(message_bot_div);  // Añade el mensaje del bot al contenedor
                chatbot.scrollTop = chatbot.scrollHeight;  // Asegura que el chat se desplace hacia abajo
            } else {
                console.error("Error en la respuesta: ", xhr.status);
            }
        };

        xhr.onerror = function() {
            console.error("Error en la solicitud.");
        };

        var data = JSON.stringify({ mensaje: message });
        xhr.send(data);  

        input.value = '';  
    }
}