<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

function hash_password(string $password): string
{
    return password_hash($password, PASSWORD_DEFAULT);
}

function verify_password(string $password, string $stored): bool
{
    return password_verify($password, $stored);
}

function issue_reset_token(string $email): string
{
    $token = bin2hex(random_bytes(32));
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $token]);
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    $pdo = db();
    $row = $pdo->prepare("SELECT token, created_at FROM reset_tokens WHERE email = ?");
    $row->execute([$email]);
    $record = $row->fetch();
    if (!$record) {
        return false;
    }
    if (!hash_equals((string)$record["token"], $token)) {
        return false;
    }
    $issuedAt = new DateTimeImmutable($record["created_at"] . " UTC");
    $now = new DateTimeImmutable("now", new DateTimeZone("UTC"));
    if ($now->getTimestamp() - $issuedAt->getTimestamp() > 60 * 60 * 24) {
        return false;
    }
    // Single-use: burn the token immediately so it can't be replayed.
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    return true;
}