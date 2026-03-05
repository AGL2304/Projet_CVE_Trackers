import { NextResponse } from "next/server";

interface JsonApiOptions {
  status?: number;
  meta?: Record<string, unknown>;
  links?: Record<string, unknown>;
  included?: unknown[];
  headers?: HeadersInit;
}

interface JsonApiError {
  status: string;
  title: string;
  detail?: string;
  code?: string;
}

export function jsonApiResponse(data: unknown, options: JsonApiOptions = {}) {
  const body = {
    jsonapi: { version: "1.1" },
    data,
    ...(options.meta ? { meta: options.meta } : {}),
    ...(options.links ? { links: options.links } : {}),
    ...(options.included ? { included: options.included } : {}),
  };

  return NextResponse.json(body, {
    status: options.status ?? 200,
    headers: options.headers,
  });
}

export function jsonApiError(
  error: JsonApiError,
  status = Number.parseInt(error.status, 10) || 500
) {
  return NextResponse.json(
    {
      jsonapi: { version: "1.1" },
      errors: [error],
    },
    { status }
  );
}
