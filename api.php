<?php
session_start();

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

define('DATA_FILE', __DIR__ . '/viro_data.json');

function readData() {
    $f = DATA_FILE;
    if (!file_exists($f)) return array();
    $d = json_decode(file_get_contents($f), true);
    return is_array($d) ? $d : array();
}

function writeData($data) {
    return file_put_contents(DATA_FILE, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX) !== false;
}

function stripPasswords($data) {
    if (!empty($data['users'])) {
        $data['users'] = array_map(function($u) {
            unset($u['pass']);
            return $u;
        }, $data['users']);
    }
    return $data;
}

$rawBody = file_get_contents('php://input');
$body    = json_decode($rawBody, true);
if (!is_array($body)) $body = array();

// L'action vient de l'URL (?action=login) ou du corps JSON
if (isset($_GET['action'])) {
    $action = $_GET['action'];
} elseif (isset($body['action'])) {
    $action = $body['action'];
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = 'load';
} else {
    $action = '';
}

switch ($action) {

    // ── LECTURE (public) ──────────────────────────────────────────────────────
    case 'load':
        $d = readData();
        echo json_encode(stripPasswords($d), JSON_UNESCAPED_UNICODE);
        break;

    // ── CONNEXION ─────────────────────────────────────────────────────────────
    case 'login':
        $login    = isset($body['login']) ? trim($body['login']) : '';
        $passHash = isset($body['pass'])  ? $body['pass']        : '';
        $d        = readData();
        $users    = isset($d['users']) ? $d['users'] : array();
        $found    = null;
        foreach ($users as $u) {
            if (isset($u['login'], $u['pass']) && $u['login'] === $login && $u['pass'] === $passHash) {
                $found = $u; break;
            }
        }
        if ($found) {
            $_SESSION['userId']   = $found['id'];
            $_SESSION['userRole'] = $found['role'];
            $safe = $found; unset($safe['pass']);
            echo json_encode(array('ok' => true, 'user' => $safe), JSON_UNESCAPED_UNICODE);
        } else {
            http_response_code(401);
            echo '{"error":"Identifiants incorrects"}';
        }
        break;

    // ── DÉCONNEXION ───────────────────────────────────────────────────────────
    case 'logout':
        session_destroy();
        echo '{"ok":true}';
        break;

    // ── SAUVEGARDE (session requise) ──────────────────────────────────────────
    case 'save':
        if (empty($_SESSION['userId'])) {
            http_response_code(401); echo '{"error":"Non authentifié"}'; break;
        }
        $role = isset($_SESSION['userRole']) ? $_SESSION['userRole'] : '';
        if (!in_array($role, array('admin', 'adjoint'))) {
            http_response_code(403); echo '{"error":"Droits insuffisants"}'; break;
        }
        $incoming = $body; unset($incoming['action']);

        // Fusionner : préserver les mots de passe existants, appliquer newPass si présent
        $stored = readData();
        $storedPasses = array();
        foreach ((isset($stored['users']) ? $stored['users'] : array()) as $u) {
            $storedPasses[$u['id']] = isset($u['pass']) ? $u['pass'] : '';
        }
        if (!empty($incoming['users'])) {
            foreach ($incoming['users'] as &$u) {
                if (!empty($u['newPass'])) {
                    $u['pass'] = $u['newPass'];
                } elseif (isset($storedPasses[$u['id']])) {
                    $u['pass'] = $storedPasses[$u['id']];
                }
                unset($u['newPass']);
            }
            unset($u);
        }
        if (!writeData($incoming)) {
            http_response_code(500); echo '{"error":"Écriture échouée"}'; break;
        }
        echo '{"ok":true}';
        break;

    // ── INITIALISATION (premier lancement uniquement) ─────────────────────────
    case 'initdata':
        if (file_exists(DATA_FILE)) {
            http_response_code(409); echo '{"error":"Données déjà initialisées"}'; break;
        }
        $data = $body; unset($data['action']);
        if (!writeData($data)) {
            http_response_code(500); echo '{"error":"Initialisation échouée"}'; break;
        }
        echo '{"ok":true}';
        break;

    default:
        http_response_code(400);
        echo json_encode(array('error' => 'Action inconnue: ' . $action));
}
