import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { Webhook } from "svix";
import { api } from "./_generated/api";

const http = httpRouter();

http.route({
 path: "/clerk-webhook",
 method: "POST",

 handler: httpAction(async (ctx, request) => {
  console.log("=== CLERK WEBHOOK RECEIVED ===");

  const webhookSecret = process.env.CLERK_WEBHOOK_SECRET;

  if (!webhookSecret) {
   console.error("CLERK_WEBHOOK_SECRET is missing");

   return new Response("Missing webhook secret", {
    status: 500,
   });
  }

  const svixId = request.headers.get("svix-id");
  const svixTimestamp = request.headers.get("svix-timestamp");
  const svixSignature = request.headers.get("svix-signature");

  console.log("Svix headers:", {
   svixId,
   svixTimestamp,
   hasSignature: !!svixSignature,
  });

  if (!svixId || !svixTimestamp || !svixSignature) {
   console.error("Missing Svix headers");

   return new Response("Missing Svix headers", {
    status: 400,
   });
  }

  // IMPORTANT:
  // Read the original request body as text.
  const body = await request.text();

  console.log("Webhook body received");

  let event: any;

  try {
   const wh = new Webhook(webhookSecret);

   // Verify the signature
   wh.verify(body, {
    "svix-id": svixId,
    "svix-timestamp": svixTimestamp,
    "svix-signature": svixSignature,
   });

   console.log("Webhook signature verified");

   // Parse the already-verified body
   event = JSON.parse(body);

   console.log("Webhook event:", event);
  } catch (error) {
   console.error("Webhook verification/parsing failed:", error);

   return new Response("Invalid webhook", {
    status: 400,
   });
  }

  console.log("Webhook event:", event);

  if (!event || !event.type) {
   console.error("Webhook event is undefined or missing type");

   return new Response("Invalid webhook event", {
    status: 400,
   });
  }

  console.log("Event type:", event.type);

  if (event.type === "user.created") {
   const {
    id,
    email_addresses,
    first_name,
    last_name,
    image_url,
   } = event.data;

   const email =
    email_addresses?.[0]?.email_address ?? "";

   const name = [first_name, last_name]
    .filter(Boolean)
    .join(" ");

   console.log("Creating/syncing user:", {
    id,
    email,
    name,
   });

   try {
    await ctx.runMutation(api.users.syncUser, {
     clerkId: id,
     email,
     name,
     image: image_url ?? undefined,
    });

    console.log("User successfully synced to Convex");
   } catch (error) {
    console.error("Error syncing user to Convex:", error);

    return new Response("Error syncing user", {
     status: 500,
    });
   }
  }

  return new Response("Webhook processed successfully", {
   status: 200,
  });
 }),
});

export default http;