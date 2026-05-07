#!/usr/bin/env python3
"""
Build spell_names.json by merging:
  1) the user's curated id->name list (high priority),
  2) every Power/<Class>_*.pow.json from d4data-master,
filtering out non-castable subpowers (_Passive, _Buff, _Effect, ...).

Run this when a new season ships and the d4data dump updates -- the
output is committed to app/static/spell_names.json so the admin UI
can fetch it without ever touching the d4data dir at runtime.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

D4_ROOT_DEFAULT = Path(
    r"C:/Users/David Schreider/Downloads/d4data-master (1)/d4data-master/json/base/meta/Power"
)
OUT_DEFAULT = Path(__file__).resolve().parents[1] / "app" / "static" / "spell_names.json"

CLASS_PREFIX = {
    "Barbarian":   "barbarian",
    "Sorcerer":    "sorcerer",
    "Druid":       "druid",
    "Necromancer": "necromancer",
    "Rogue":       "rogue",
    "Spiritborn":  "spiritborn",
    "Paladin":     "paladin",
    "Warlock":     "warlock",
}

CURATED = {
    "barbarian": {
        200765:  "Bash",
        204513:  "Call Of The Ancients",
        203177:  "Charge",
        204450:  "Challenging Shout",
        211938:  "Challenging Shout (Alt)",
        207827:  "Death Blow",
        203268:  "Double Swing",
        200787:  "Flay",
        206432:  "Frenzy",
        186358:  "Ground Stomp",
        213673:  "Hammer Of Ancients",
        217175:  "Iron Maelstrom",
        207895:  "Iron Maelstrom (Alt)",
        201633:  "Iron Skin",
        199516:  "Kick",
        196545:  "Leap",
        199206:  "Leap (Alt)",
        206504:  "Lunging Strike",
        1611316: "Mighty Throw",
        208683:  "Mighty Throw (Alt)",
        204662:  "Rallying Cry",
        375484:  "Rallying Cry (Alt)",
        208333:  "Rend",
        208499:  "Rupture",
        964631:  "Steel Grasp",
        210670:  "Steel Grasp (Alt)",
        202484:  "Upheaval",
        194096:  "War Cry",
        184600:  "War Cry (Alt)",
        206435:  "Whirlwind",
        211871:  "Wrath Of The Berserker",
    },
    "druid": {
        566517:  "Blood Howl",
        238345:  "Boulder",
        266570:  "Cataclysm",
        439581:  "Claw",
        280119:  "Cyclone Armor",
        336238:  "Debilitating Roar",
        543387:  "Earth Spike",
        333421:  "Earthen Bulwark",
        267021:  "Grizzly Rage",
        289513:  "Heightened Senses",
        258990:  "Hurricane",
        394251:  "Lacerate",
        313893:  "Landslide",
        548399:  "Lightning Storm",
        309070:  "Maul",
        351722:  "Petrify",
        314601:  "Poison Creeper",
        272138:  "Pulverize",
        290969:  "Quickshift",
        416337:  "Rabies",
        281516:  "Ravens",
        1256958: "Shred",
        1473878: "Stone Burst",
        309320:  "Storm Strike",
        304065:  "Tornado",
        258243:  "Trample",
        356587:  "Wind Shear",
        265663:  "Wolves",
    },
    "necromancer": {
        493644:  "Army Of The Dead",
        501629:  "Blood Lance",
        493422:  "Blood Mist",
        592163:  "Blood Surge",
        592435:  "Blood Wave",
        481293:  "Blight",
        493453:  "Bone Prison",
        432258:  "Bone Spear",
        495653:  "Bone Spirit",
        427557:  "Bone Splinters",
        493622:  "Bone Storm",
        432897:  "Corpse Explosion",
        463349:  "Corpse Tendrils",
        463175:  "Decompose",
        434035:  "Decrepify",
        433402:  "Golem Control",
        484661:  "Hemorrhage",
        493195:  "Iron Maiden",
        1059157: "Raise Skeleton",
        432896:  "Reap",
        481785:  "Sever",
        1644584: "Soulrift",
    },
    "paladin": {
        2329865: "Advance",
        2292204: "Aegis",
        2297125: "Arbiter Of Justice",
        2107555: "Blessed Hammer",
        2082021: "Blessed Shield",
        2265693: "Brandish",
        2097465: "Clash",
        2226109: "Condemn",
        2283781: "Consecration",
        2187578: "Defiance Aura",
        2120228: "Divine Lance",
        2106904: "Falling Star",
        2187741: "Fanaticism Aura",
        2301078: "Fortress",
        2273081: "Heaven’s Fury",
        2174078: "Holy Bolt",
        2297097: "Holy Light Aura",
        2256888: "Paladin Evade",
        2261380: "Purify",
        2303677: "Rally",
        2087548: "Shield Bash",
        2466077: "Shield Charge",
        2100457: "Spear Of The Heavens",
        2132824: "Zeal",
        2302974: "Zenith",
    },
    "rogue": {
        439762:  "Barrage",
        399111:  "Blade Shift",
        389667:  "Caltrop",
        359246:  "Cold Imbuement",
        794965:  "Concealment",
        1690398: "Dance Of Knives",
        786381:  "Dark Shroud",
        358761:  "Dash",
        421161:  "Death Trap",
        358339:  "Flurry",
        416272:  "Forceful Arrow",
        363402:  "Heartseeker",
        416057:  "Invigorating Strike",
        377137:  "Penetrating Shot",
        358508:  "Poison Imbuement",
        416528:  "Poison Trap",
        364877:  "Puncture",
        400232:  "Rain Of Arrows",
        355926:  "Rapid Fire",
        357628:  "Shadow Clone",
        380288:  "Shadow Imbuement",
        355606:  "Shadow Step",
        356162:  "Smoke Grenade",
        398258:  "Twisting Blade",
    },
    "sorcerer": {
        297902:  "Arc Lash",
        514030:  "Ball Lightning",
        291403:  "Blizzard",
        292757:  "Chain Lightning",
        171937:  "Charged Bolts",
        291827:  "Deep Freeze",
        1627075: "Familiars",
        153249:  "Fire Bolt",
        165023:  "Fireball",
        111422:  "Firewall",
        167341:  "Flame Shield",
        287256:  "Frost Bolt",
        291215:  "Frost Nova",
        291347:  "Frozen Orb",
        146743:  "Hydra",
        297039:  "Ice Armor",
        291492:  "Ice Blade",
        293195:  "Ice Shards",
        292737:  "Incinerate",
        294198:  "Inferno",
        296998:  "Meteor",
        143483:  "Spark",
        292074:  "Spear",
        288106:  "Teleport",
        959728:  "Teleport (Enchanted)",
        517417:  "Unstable Currents",
    },
    "spiritborn": {
        1871764: "Armored Hide",
        1871825: "Concussive Stomp",
        1871819: "Counterattack",
        1519050: "Crushing Hand",
        1648395: "Intricacy",
        1871823: "Payback",
        1519048: "Quill Volley",
        1640931: "Rake",
        1862773: "Ravager",
        1871807: "Razor Wings",
        1817045: "Rock Splitter",
        1871761: "Rushing Claw",
        1871801: "Scourge",
        1871821: "Soar",
        1836008: "Stinger",
        1648393: "Supremacy",
        1663210: "The Devourer",
        1663206: "The Hunter",
        1663208: "The Protector",
        1663204: "The Seeker",
        1834473: "Thrash",
        1834476: "Thunderspike",
        1871809: "Touch Of Death",
        1871813: "Toxic Skin",
        1489641: "Vortex",
        1834471: "Withering Fist",
    },
}

# Subpower / passive / VFX-helper suffixes — skipped from d4data so the
# dropdown isn't drowned in non-castable internal entries.
SUFFIX_BLOCKLIST = re.compile(
    r"(?i)(?:_Passive|_Channel|_Channeled|_Internal|_Summon|_Summoned|"
    r"_Pet|_Helper|_Indicator|_Marker|_Buff|_Damage|_Tooltip|_Test|"
    r"_Probe|_Loop|_LoopSafe|_OnDeath|_OnHit|_Active2|_Discharge|"
    r"_Effect|_Aoe|_DoT|_Tick|_Splash|_Travel|_Projectile|_PrimaryProc|"
    r"_AreaDamage|_Visuals)$"
)

# Internal-name fragments anywhere in the stem that signal "not the
# player-cast power" (e.g. CalloftheAncients_Bash is the AI helper, not
# the active CallOfTheAncients ult itself).
INNER_BLOCKLIST = re.compile(
    r"(?i)(?:_OnHit|_Indicator|_Marker|_Helper|Internal|_Passive)"
)


def humanize(camel: str) -> str:
    """Insert spaces between CamelCase boundaries; replace underscores."""
    s = re.sub(r"([a-z\d])([A-Z])", r"\1 \2", camel)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    return s.replace("_", " ").strip()


def main(d4_root: Path = D4_ROOT_DEFAULT, out: Path = OUT_DEFAULT) -> None:
    merged: dict[str, dict[str, str]] = {}

    # Curated wins.
    for klass, items in CURATED.items():
        for sid, name in items.items():
            merged[str(sid)] = {"name": name, "class": klass}

    added = 0
    skipped = 0
    if d4_root.exists():
        for fpath in sorted(d4_root.glob("*.pow.json")):
            stem = fpath.name[: -len(".pow.json")]
            klass = None
            tail = stem
            for prefix, slug in CLASS_PREFIX.items():
                if stem.startswith(prefix + "_"):
                    klass = slug
                    tail = stem[len(prefix) + 1:]
                    break
            if not klass:
                continue
            if SUFFIX_BLOCKLIST.search(tail) or INNER_BLOCKLIST.search(tail):
                skipped += 1
                continue
            try:
                with fpath.open("r", encoding="utf-8") as f:
                    doc = json.load(f)
            except Exception:
                continue
            sid = doc.get("__snoID__")
            if not isinstance(sid, int):
                continue
            key = str(sid)
            if key in merged:
                continue   # curated already covers it
            pretty = humanize(tail)
            merged[key] = {"name": pretty, "class": klass}
            added += 1

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=0, sort_keys=True)

    curated_total = sum(len(v) for v in CURATED.values())
    print(f"curated:  {curated_total}")
    print(f"d4data added:  {added}")
    print(f"d4data skipped (subpowers): {skipped}")
    print(f"total:    {len(merged)}")
    print(f"output:   {out}")
    print(f"size:     {out.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
