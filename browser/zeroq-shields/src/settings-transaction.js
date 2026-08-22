export async function applyVerifiedSettings({
  desired,
  previous,
  apply,
  verify,
  persist,
  recordFailure
}) {
  try {
    await apply(desired);
    const verification = await verify(desired);
    await persist(desired, verification, false);
    return { settings: desired, verification, rollback: "not_needed" };
  } catch (error) {
    let rollback = "failed";
    let rollbackError = null;
    try {
      await apply(previous);
      const verification = await verify(previous);
      await persist(previous, verification, true);
      rollback = "verified";
    } catch (caught) {
      rollbackError = caught;
    }
    await recordFailure({ error, rollback, rollbackError });
    throw error;
  }
}
