const ALLOWED_ATTRIBUTES = /^(class|style|title|role|aria-[a-z]+|data-[a-z-]+)$/;

type Leaf = Node | string | number | bigint | boolean | null | undefined;

export type Child = Leaf | Child[];

export type Attrs = Record<string, string | number | boolean | null | undefined>;

function nodes(children: Child[]): (Node | string)[] {
  return ((children as unknown[]).flat(Infinity) as Leaf[])
    .filter((child): child is Exclude<Leaf, null | undefined | false> => child !== null && child !== undefined && child !== false)
    .map(child => (typeof child === 'object' && typeof child.nodeType === 'number' ? child : String(child)));
}

export function h(tag: string, attrs?: Attrs | null, ...children: Child[]): HTMLElement {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs ?? {})) {
    if (!ALLOWED_ATTRIBUTES.test(name)) throw new Error(`h(): attribute ${name} is not allowed`);
    if (value === null || value === undefined || value === false) continue;
    el.setAttribute(name, String(value));
  }
  el.append(...nodes(children));
  return el;
}

export function fill<T extends Element>(el: T, ...children: Child[]): T {
  el.replaceChildren(...nodes(children));
  return el;
}

export function paragraphs(blocks: Child[]): Child[] {
  return blocks.flatMap((block, i) => (i ? [h('br'), h('br'), block] : [block]));
}
