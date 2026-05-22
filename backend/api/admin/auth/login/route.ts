import { z } from "zod";
import { NextRequest, NextResponse } from "next/server";
import {
  ADMIN_SESSION_COOKIE_NAME,
  createAdminSessionToken,
  getAdminCookieOptions,
  verifyAdminCredentials,
} from "@/lib/admin-auth";

const loginSchema = z.object({
  username: z.string().trim().min(1),
  password: z.string().min(1),
});

export async function POST(request: NextRequest) {
  try {
    const parsed = loginSchema.safeParse(await request.json());
    if (!parsed.success) {
      return NextResponse.json(
        {
          error: "Invalid credentials payload",
        },
        { status: 400 }
      );
    }

    const { username, password } = parsed.data;
    if (!verifyAdminCredentials(username, password)) {
      return NextResponse.json(
        {
          error: "Invalid username or password",
        },
        { status: 401 }
      );
    }

    const sessionToken = createAdminSessionToken(username);
    const response = NextResponse.json({
      authenticated: true,
      username,
    });
    response.cookies.set(ADMIN_SESSION_COOKIE_NAME, sessionToken, getAdminCookieOptions());
    return response;
  } catch (error) {
    console.error("POST /api/admin/auth/login failed", error);
    return NextResponse.json(
      {
        error: "Unable to login",
      },
      { status: 500 }
    );
  }
}
