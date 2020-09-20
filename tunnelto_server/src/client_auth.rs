use tunnelto_lib::{ClientHello, ClientId, ServerHello, ClientType};
use warp::filters::ws::{WebSocket, Message};
use futures::{SinkExt, StreamExt};
use crate::connected_clients::Connections;
use log::error;
use crate::BLOCKED_SUB_DOMAINS;

pub struct ClientHandshake {
    pub id: ClientId,
    pub sub_domain: String,
    pub is_anonymous: bool,
}

pub async fn auth_client_handshake(mut websocket: WebSocket) -> Option<(WebSocket, ClientHandshake)> {
    let client_hello_data = match websocket.next().await {
        Some(Ok(msg)) => msg,
        _ => {
            error!("no client init message");
            return None
        },
    };

    auth_client(client_hello_data.as_bytes(), websocket).await
}

async fn auth_client(client_hello_data: &[u8], mut websocket: WebSocket) -> Option<(WebSocket, ClientHandshake)> {
    // parse the client hello
    let client_hello:ClientHello = match serde_json::from_slice(client_hello_data) {
        Ok(ch) => ch,
        Err(e) => {
            error!("invalid client hello: {}", e);
            let data = serde_json::to_vec(&ServerHello::AuthFailed).unwrap_or_default();
            let _ = websocket.send(Message::binary(data)).await;
            return None
        }
    };

    let sub_domain = match client_hello.sub_domain {
        Some(requested_sub_domain) => {
            let (ws, sub_domain) = match sanitize_sub_domain_and_pre_validate(websocket, requested_sub_domain, &client_hello.id).await {
                Some(s) => s,
                None => return None,
            };
            websocket = ws;

            sub_domain
        },
        None => {
            ServerHello::random_domain()
        }
    };

    Some((websocket, ClientHandshake { id: client_hello.id, sub_domain, is_anonymous: client_hello.client_type == ClientType::Anonymous }))
}

async fn sanitize_sub_domain_and_pre_validate(mut websocket: WebSocket, requested_sub_domain: String, client_id: &ClientId) -> Option<(WebSocket, String)>{
    // ignore uppercase
    let sub_domain = requested_sub_domain.to_lowercase();

    if sub_domain.chars().filter(|c| !c.is_alphanumeric()).count() > 0 {
        error!("invalid client hello: only alphanumeric chars allowed!");
        let data = serde_json::to_vec(&ServerHello::InvalidSubDomain).unwrap_or_default();
        let _ = websocket.send(Message::binary(data)).await;
        return None
    }

    // ensure this sub-domain isn't taken
    let existing_client = Connections::client_for_host(&sub_domain);
    if existing_client.is_some() && Some(client_id) != existing_client.as_ref() {
        error!("invalid client hello: requested sub domain in use already!");
        let data = serde_json::to_vec(&ServerHello::SubDomainInUse).unwrap_or_default();
        let _ = websocket.send(Message::binary(data)).await;
        return None
    }

    // ensure it's not a restricted one
    if BLOCKED_SUB_DOMAINS.contains(&sub_domain) {
        error!("invalid client hello: sub-domain restrict!");
        let data = serde_json::to_vec(&ServerHello::SubDomainInUse).unwrap_or_default();
        let _ = websocket.send(Message::binary(data)).await;
        return None
    }

    Some((websocket, sub_domain))
}
