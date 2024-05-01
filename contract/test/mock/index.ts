import { batch1024 } from "./batch1024"
import { batch128 } from "./batch128"
import { batch16 } from "./batch16"
import { batch2 } from "./batch2"
import { batch256 } from "./batch256"
import { batch32 } from "./batch32"
import { batch4 } from "./batch4"
import { batch512 } from "./batch512"
import { batch64 } from "./batch64"
import { batch8 } from "./batch8"

const g = [
    14503582948638727084502759502994279163222108009153332193323880774870858770036n,
    14591073697149083878648039582988519715702082715595253321641344990827767900840n,
]

const h = [
    598134931736234900467939765247253867024649852659867435941841640401379183793n,
    15738093922633515834030325254155237326871962654522925907436502223905379545674n,
    14919326580790664754690105099088381271955422709270798132195168786371643203877n,
    18145374548316659229864951505936810867524529744013061164160124189068667257707n,
]

const batch = [
    batch2,
    batch4,
    batch8,
    batch16,
    batch32,
    batch64,
    batch128,
    batch256,
    batch512,
    batch1024,
]// map((s: { [key: string]: string[] }) => {
//     let b: { [key: string]: bigint[] } = {}
//     for (let key in s)
//         b[key] = s[key].map((value: string) => BigInt(value))
//     return b
// })

export const mock = {
    batch,
    g,
    h,
}