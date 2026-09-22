'use strict';
/** Общие константы движка Nukefy. */
const MINER_PORTS = [1443, 14444, 2222, 3333, 3334, 3335, 3336, 3337, 3339, 3444, 4444, 5555, 5868, 6666, 7777, 8008, 8055, 8113, 13506, 13535];

const CATS = {
  virus: { label: 'Вирусы' },
  trojan: { label: 'Трояны' },
  miner: { label: 'Майнеры' },
  risk: { label: 'Риски / PUA' },
};

const SEV_LABEL = { 1: 'низкая', 2: 'средняя', 3: 'высокая', 4: 'критическая' };

module.exports = { MINER_PORTS, CATS, SEV_LABEL };
