import { yaramailCallbackRoute } from "./workers/routes/yaramail-callback";
import { Hono } from "hono";

const app = new Hono();
app.route("/", yaramailCallbackRoute);

// test
