import { ScpCommandArgs } from "./shared";
import yargs from "yargs";
export declare const scpCommand: (yargs: yargs.Argv<{}>) => yargs.Argv<ScpCommandArgs>;
