// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Direct unit tests for the filename helpers in
 * `workers/security/attachments.ts` — ordinary filenames only.
 */

import { describe, expect, it } from "vitest";
import { classifyAttachment, extractExtension } from "../../workers/security/attachments";

describe("extractExtension", () => {
	it("returns the lowercased final extension", () => {
		expect(extractExtension("report.pdf")).toBe("pdf");
		expect(extractExtension("REPORT.PDF")).toBe("pdf");
		expect(extractExtension("Budget.XlSx")).toBe("xlsx");
	});

	it("returns only the last segment of a multi-dot name", () => {
		expect(extractExtension("archive.tar.gz")).toBe("gz");
		expect(extractExtension("q3.summary.v2.docx")).toBe("docx");
	});

	it("returns an empty string when there is no extension", () => {
		expect(extractExtension("README")).toBe("");
		expect(extractExtension(".bashrc")).toBe("");
		expect(extractExtension("")).toBe("");
		expect(extractExtension(null)).toBe("");
		expect(extractExtension(undefined)).toBe("");
	});
});

describe("classifyAttachment", () => {
	it("classifies common document and image types as safe", () => {
		for (const name of ["contract.pdf", "notes.docx", "sheet.xlsx", "deck.pptx", "photo.jpg", "notes.txt"]) {
			expect(classifyAttachment(name, null).category).toBe("safe");
		}
	});

	it("classifies a file with no extension as safe with an empty ext", () => {
		expect(classifyAttachment("README", "text/plain")).toEqual({ category: "safe", ext: "" });
	});

	it("classifies a plain .exe as executable regardless of case", () => {
		expect(classifyAttachment("setup.exe", "application/octet-stream")).toEqual({ category: "executable", ext: "exe" });
		expect(classifyAttachment("SETUP.EXE", null)).toEqual({ category: "executable", ext: "exe" });
	});

	it("classifies disk images as containers and macro-enabled Office files as macro_office", () => {
		expect(classifyAttachment("image.iso", null)).toEqual({ category: "container", ext: "iso" });
		expect(classifyAttachment("forecast.xlsm", null)).toEqual({ category: "macro_office", ext: "xlsm" });
	});

	it("classifies a multi-dot archive by its final extension", () => {
		expect(classifyAttachment("archive.tar.gz", "application/gzip")).toEqual({ category: "safe", ext: "gz" });
	});

	it("ignores the mimetype", () => {
		expect(classifyAttachment("contract.pdf", "application/x-msdownload")).toEqual({ category: "safe", ext: "pdf" });
	});
});
