import _traverse, { type NodePath, type TraverseOptions } from "@babel/traverse";
import _generate, { type GeneratorOptions, type GeneratorResult } from "@babel/generator";
import type * as t from "@babel/types";

export type TraverseFn = (parent: t.Node, opts?: TraverseOptions) => void;
export type GenerateFn = (
  ast: t.Node,
  opts?: GeneratorOptions,
  code?: string,
) => GeneratorResult;

export const traverse: TraverseFn =
  typeof _traverse === "function"
    ? (_traverse as unknown as TraverseFn)
    : (_traverse as unknown as { default: TraverseFn }).default;

export const generate: GenerateFn =
  typeof _generate === "function"
    ? (_generate as unknown as GenerateFn)
    : (_generate as unknown as { default: GenerateFn }).default;

export type { NodePath };
