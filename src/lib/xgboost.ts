/**
 * XGBoost inference engine (gradient-boosted decision trees).
 *
 * The model in `xgb-model.json` was trained offline with the real XGBoost
 * library (objective: binary:logistic, 70 boosting rounds, max_depth 4) on a
 * labelled phishing/benign URL-feature dataset. Only the resulting tree
 * ensemble is shipped, so scoring runs fully server-side with no Python
 * runtime and no network call.
 *
 * Node layout (compact): [featureIndex, threshold, yesChild, noChild]
 * Leaf layout:           [-1, leafValue, 0, 0]
 * Split rule mirrors XGBoost: go to `yes` when value < threshold.
 */
import model from "./xgb-model.json";

type Node = [number, number, number, number];
type Tree = Node[];

const TREES = model.trees as unknown as Tree[];
export const XGB_FEATURES = model.features as string[];
export const XGB_METRICS = model.metrics as {
  accuracy: number;
  auc: number;
  trainedOn: number;
  rounds: number;
  maxDepth: number;
  learningRate: number;
};
export const XGB_GAIN = model.gain as Record<string, number>;

const BASE_MARGIN = Math.log(model.baseScore / (1 - model.baseScore)); // logit(base_score)

export type FeatureVector = Record<string, number>;

function toArray(fv: FeatureVector): number[] {
  return XGB_FEATURES.map((f) => {
    const v = fv[f];
    return Number.isFinite(v) ? (v as number) : 0;
  });
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

/** Raw ensemble margin (sum of leaf values + base margin). */
function margin(x: number[]): number {
  let sum = BASE_MARGIN;
  for (const tree of TREES) {
    let i = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const node = tree[i];
      if (node[0] === -1) {
        sum += node[1];
        break;
      }
      i = x[node[0]] < node[1] ? node[2] : node[3];
    }
  }
  return sum;
}

export interface XgbPrediction {
  /** Phishing probability, 0-1. */
  probability: number;
  /** Raw log-odds margin. */
  margin: number;
  /** Per-feature signed contribution to the margin (Saabas path attribution). */
  contributions: { feature: string; value: number; contribution: number }[];
  /** Model confidence 0-100, derived from distance of the margin from the decision boundary. */
  confidence: number;
}

/**
 * Saabas / "tree interpreter" attribution: for every decision node the change
 * in the subtree mean prediction is credited to the splitting feature. Summed
 * across all boosting rounds this decomposes the margin exactly:
 *   margin = baseMargin + sum(contributions)
 */
function attribute(x: number[]): number[] {
  const contribs = new Array<number>(XGB_FEATURES.length).fill(0);

  const meanCache = new Map<Tree, number[]>();
  const subtreeMean = (tree: Tree): number[] => {
    const cached = meanCache.get(tree);
    if (cached) return cached;
    const means = new Array<number>(tree.length).fill(0);
    // children always have a higher index than their parent, so a reverse pass works
    for (let i = tree.length - 1; i >= 0; i--) {
      const n = tree[i];
      means[i] = n[0] === -1 ? n[1] : (means[n[2]] + means[n[3]]) / 2;
    }
    meanCache.set(tree, means);
    return means;
  };

  for (const tree of TREES) {
    const means = subtreeMean(tree);
    let i = 0;
    while (tree[i][0] !== -1) {
      const n = tree[i];
      const next = x[n[0]] < n[1] ? n[2] : n[3];
      contribs[n[0]] += means[next] - means[i];
      i = next;
    }
  }
  return contribs;
}

export function predict(fv: FeatureVector): XgbPrediction {
  const x = toArray(fv);
  const m = margin(x);
  const raw = attribute(x);

  const contributions = XGB_FEATURES.map((feature, i) => ({
    feature,
    value: x[i],
    contribution: Math.round(raw[i] * 1000) / 1000,
  }))
    .filter((c) => Math.abs(c.contribution) > 0.001)
    .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));

  const probability = sigmoid(m);
  // Confidence: how far the decision is from the 0.5 boundary, squashed to 0-100.
  const confidence = Math.round(Math.min(99, 50 + 49 * Math.tanh(Math.abs(m) / 3)));

  return { probability, margin: m, contributions, confidence };
}
