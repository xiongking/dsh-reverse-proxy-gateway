/**
 * 认证失败限速的单元测试。
 * 时钟由外部注入，因此不用真的等五分钟。
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createAttemptLimiter } from '../index.mjs';

/** 可控时钟。 */
function clock(start = 1_000_000) {
  let current = start;
  return {
    now: () => current,
    advance(ms) {
      current += ms;
    },
  };
}

describe('createAttemptLimiter', () => {
  it('未达阈值时不锁，达到阈值立刻锁', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 3, windowMs: 1000, lockMs: 5000, now: time.now });

    assert.equal(limiter.check('a').locked, false);
    limiter.fail('a');
    limiter.fail('a');
    assert.equal(limiter.check('a').locked, false);
    const state = limiter.fail('a');
    assert.equal(state.locked, true);
    assert.ok(state.retryAfterMs > 0);
    assert.equal(limiter.check('a').locked, true);
  });

  it('retryAfter 随时间递减', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 1, windowMs: 1000, lockMs: 5000, now: time.now });
    const locked = limiter.fail('a');
    assert.equal(locked.retryAfterMs, 5000);
    time.advance(2000);
    const later = limiter.check('a');
    assert.equal(later.locked, true);
    assert.equal(later.retryAfterMs, 3000);
  });

  it('锁定到期后自动解锁', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 1, windowMs: 1000, lockMs: 5000, now: time.now });
    limiter.fail('a');
    time.advance(5001);
    assert.equal(limiter.check('a').locked, false);
  });

  it('窗口内没攒够失败就过期清零', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 3, windowMs: 1000, lockMs: 5000, now: time.now });
    limiter.fail('a');
    limiter.fail('a');
    time.advance(1001); // 超出窗口
    limiter.fail('a');
    limiter.fail('a');
    // 第二窗口只累计到 2 次，还不到 3 次。
    assert.equal(limiter.check('a').locked, false);
    assert.equal(limiter.fail('a').locked, true);
  });

  it('不同来源互不影响', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 2, windowMs: 1000, lockMs: 5000, now: time.now });
    limiter.fail('a');
    limiter.fail('a');
    assert.equal(limiter.check('a').locked, true);
    assert.equal(limiter.check('b').locked, false);
  });

  it('成功一次即清零', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 2, windowMs: 1000, lockMs: 5000, now: time.now });
    limiter.fail('a');
    assert.equal(limiter.check('a').locked, false);
    limiter.reset('a');
    limiter.fail('a');
    // 若没有清零，这一次就是第 2 次失败而锁定。
    assert.equal(limiter.check('a').locked, false);
  });

  it('空键不记账，也不制造锁定', () => {
    const limiter = createAttemptLimiter({ maxFails: 1 });
    assert.deepEqual(limiter.check(''), { locked: false, retryAfterMs: 0 });
    assert.deepEqual(limiter.fail(''), { locked: false, retryAfterMs: 0 });
    limiter.reset('');
    assert.equal(limiter.size(), 0);
  });

  it('默认阈值是 5 次', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ now: time.now });
    for (let index = 0; index < 4; index += 1) limiter.fail('a');
    assert.equal(limiter.check('a').locked, false);
    assert.equal(limiter.fail('a').locked, true);
  });

  it('同一份凭据短时间内重复失败只算一次（浏览器会把它重发到每个子资源）', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 3, windowMs: 60_000, lockMs: 5000, now: time.now });
    // 同一个错误密码连续来 10 次，等同于页面加载时浏览器自动重发。
    for (let index = 0; index < 10; index += 1) {
      assert.equal(limiter.fail('tcp:1.2.3.4', 'print-old').locked, false);
    }
    // 换了一份凭据才开始累加。
    limiter.fail('tcp:1.2.3.4', 'print-new-1');
    limiter.fail('tcp:1.2.3.4', 'print-new-2');
    assert.equal(limiter.fail('tcp:1.2.3.4', 'print-new-3').locked, true);
  });

  it('同一份凭据超出去重窗口后继续计数，不能靠重放同一个密码绕过限速', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 3, windowMs: 60_000, lockMs: 5000, dedupeMs: 5000, now: time.now });
    assert.equal(limiter.fail('tcp:1.2.3.4', 'print-same').locked, false);
    // 窗口内重复：不累加。
    time.advance(1000);
    assert.equal(limiter.fail('tcp:1.2.3.4', 'print-same').locked, false);
    time.advance(1000);
    assert.equal(limiter.fail('tcp:1.2.3.4', 'print-same').locked, false);
    // 过了 5 秒再重放，就要算次数了：第二次、第三次记账，第三次当场锁定。
    time.advance(5000);
    assert.equal(limiter.fail('tcp:1.2.3.4', 'print-same').locked, false);
    time.advance(1000);
    assert.equal(limiter.fail('tcp:1.2.3.4', 'print-same').locked, false);
    time.advance(5000);
    assert.equal(limiter.fail('tcp:1.2.3.4', 'print-same').locked, true);
  });

  it('不带摘要时按老规矩每次都算', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 2, now: time.now });
    limiter.fail('a');
    assert.equal(limiter.fail('a').locked, true);
  });

  it('超过 maxKeys 时清掉最早插入的键，内存不会无界增长', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 5, windowMs: 60_000, lockMs: 60_000, maxKeys: 8, sweepEvery: 1, now: time.now });
    for (let index = 0; index < 50; index += 1) limiter.fail(`xff:10.0.0.${index}`);
    assert.ok(limiter.size() <= 8, `实际 ${limiter.size()}`);
    // 被丢掉的只可能是最早的那批，最近一次仍然记着。
    assert.equal(limiter.check('xff:10.0.0.49').locked, false);
  });

  it('sweep 能主动清掉过期的键', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 5, windowMs: 1000, lockMs: 1000, sweepEvery: 1000, now: time.now });
    limiter.fail('a');
    limiter.fail('b');
    assert.equal(limiter.size(), 2);
    time.advance(5000);
    assert.equal(limiter.sweep(), 0);
  });

  it('被锁的记录在 sweep 时保留，直到锁定自然到期', () => {
    const time = clock();
    const limiter = createAttemptLimiter({ maxFails: 1, windowMs: 1000, lockMs: 10_000, sweepEvery: 1000, now: time.now });
    limiter.fail('a');
    time.advance(5000);
    assert.equal(limiter.sweep(), 1);
    assert.equal(limiter.check('a').locked, true);
  });
});
