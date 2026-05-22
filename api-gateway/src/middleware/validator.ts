import { Request, Response, NextFunction } from 'express';

// Secure list of authorized audit targets
const AUTHORIZED_TARGETS = new Set(['localhost', '127.0.0.1', 'scanme.nmap.org']);

/**
 * Validates that the requested target is fully authorized and safe for security scans.
 * Prevents command injection and malicious scanning of unauthorized networks.
 */
export const validateAuditTarget = (req: Request, res: Response, next: NextFunction): void => {
  const { target } = req.body;

  // 1. Check if target is present
  if (!target || typeof target !== 'string') {
    res.status(400).json({
      error: 'Invalid Request',
      message: 'The "target" field must be a valid, non-empty string.'
    });
    return;
  }

  // 2. Sanitize the target input
  let cleanTarget = target.trim().toLowerCase();

  // Remove protocol prefixes if user accidentally included them (e.g., http://, https://)
  cleanTarget = cleanTarget.replace(/^(https?:\/\/)?(www\.)?/, '');
  
  // Remove paths, port numbers, or query parameters
  cleanTarget = cleanTarget.split('/')[0];
  cleanTarget = cleanTarget.split(':')[0];

  // 3. Strict whitelist check
  if (!AUTHORIZED_TARGETS.has(cleanTarget)) {
    console.warn(`[SecOps Alert] Unauthorized scan attempt blocked for target: "${target}"`);
    res.status(403).json({
      error: 'Access Denied',
      message: 'Unauthorized target. Scans are strictly restricted to: localhost, 127.0.0.1, and scanme.nmap.org.'
    });
    return;
  }

  // Bind the sanitized target to the request body so controllers use the sanitized version
  req.body.sanitizedTarget = cleanTarget;
  next();
};
