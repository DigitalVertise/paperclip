import { createHash } from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { instanceUserRoles, invites } from "@paperclipai/db";
import { logger } from "./middleware/logger.js";

/**
 * Headless equivalent of `paperclipai auth bootstrap-ceo` for hosts without a
 * shell (e.g. Render free tier). When PAPERCLIP_BOOTSTRAP_INVITE_TOKEN is set
 * and the instance has no admin yet, ensure an unaccepted bootstrap_ceo invite
 * exists for that token. The first person to open /invite/<token> becomes the
 * admin; after that this is a no-op. Remove the env var once bootstrapped.
 */
export async function ensureBootstrapInviteFromEnv(db: any, publicBaseUrl?: string): Promise<void> {
  const token = process.env.PAPERCLIP_BOOTSTRAP_INVITE_TOKEN?.trim();
  if (!token) return;
  if (token.length < 32) {
    logger.warn("PAPERCLIP_BOOTSTRAP_INVITE_TOKEN ignored: must be at least 32 characters");
    return;
  }

  try {
    const adminCount = await db
      .select()
      .from(instanceUserRoles)
      .where(eq(instanceUserRoles.role, "instance_admin"))
      .then((rows: unknown[]) => rows.length);
    if (adminCount > 0) {
      logger.info("Bootstrap invite skipped: instance already has an admin. You can remove PAPERCLIP_BOOTSTRAP_INVITE_TOKEN.");
      return;
    }

    const tokenHash = createHash("sha256").update(token).digest("hex");
    const now = new Date();
    const existing = await db
      .select()
      .from(invites)
      .where(
        and(
          eq(invites.inviteType, "bootstrap_ceo"),
          eq(invites.tokenHash, tokenHash),
          isNull(invites.revokedAt),
          isNull(invites.acceptedAt),
          gt(invites.expiresAt, now),
        ),
      )
      .then((rows: unknown[]) => rows.length);

    if (existing === 0) {
      await db.insert(invites).values({
        inviteType: "bootstrap_ceo",
        tokenHash,
        allowedJoinTypes: "human",
        expiresAt: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000),
        invitedByUserId: "system",
      });
    }

    const base = (publicBaseUrl ?? "").replace(/\/+$/, "");
    logger.info(`Bootstrap admin invite ready: ${base || "<public-url>"}/invite/<PAPERCLIP_BOOTSTRAP_INVITE_TOKEN>`);
  } catch (err) {
    logger.error({ err }, "Could not ensure bootstrap invite from env");
  }
}
