# Brute Force Correlation Detection

## Description
Detects brute-force attacks followed by successful login.

## Events Used
- Event ID :4625 (Failed login)
- Event ID: 4624 (Successful login)

## Detection Logic
Multiple failures -> successful login from same IP

## Outcome
Account compromise detection
