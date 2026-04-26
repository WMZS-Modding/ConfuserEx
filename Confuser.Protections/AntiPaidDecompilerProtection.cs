using Confuser.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Linq;
using System.Collections.Generic;

namespace Confuser.Protections
{
    internal class AntiPaidDecompilerProtection : Protection
    {
        public override string Name { get { return "Anti-Paid Decompiler Protection"; } }
        public override string Description { get { return "Blocks IDA Pro, Hex-Rays, ByteCode Viewer, and commercial .NET decompilers"; } }
        public override string Id { get { return "anti paid decompiler"; } }
        public override string FullId { get { return "Ki.AntiPaidDecompilerProtection"; } }
        public override ProtectionPreset Preset { get { return ProtectionPreset.Aggressive; } }

        protected override void Initialize(ConfuserContext context) { }

        protected override void PopulatePipeline(ProtectionPipeline pipeline)
        {
            pipeline.InsertPostStage(PipelineStage.ProcessModule, new AntiPaidDecompilerPhase(this));
        }

        class AntiPaidDecompilerPhase : ProtectionPhase
        {
            public AntiPaidDecompilerPhase(AntiPaidDecompilerProtection parent) : base(parent) { }
            public override ProtectionTargets Targets { get { return ProtectionTargets.Methods; } }
            public override string Name { get { return "Anti-Paid Decompiler"; } }

            protected override void Execute(ConfuserContext context, ProtectionParameters parameters)
            {
                foreach (var method in parameters.Targets.OfType<MethodDef>())
                {
                    if (!method.HasBody) continue;

                    InjectAntiDecompilerPayload(method);
                }
            }

            private void InjectAntiDecompilerPayload(MethodDef method)
            {
                var module = method.Module;
                var corlib = module.CorLibTypes;
                var voidType = corlib.Void;
                var objType = corlib.Object;

                var originalBody = method.Body.Instructions.ToList();
                method.Body.Instructions.Clear();

                var dispatchTable = new List<Instruction>();
                var fragmentCount = originalBody.Count / 10 + 2;

                for (int i = 0; i < fragmentCount; i++)
                {
                    var fragmentLabel = Instruction.Create(OpCodes.Nop);
                    dispatchTable.Add(fragmentLabel);
                }

                /*
                var decryptionKey = (uint)new Random().Next();
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, (int)decryptionKey));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

                method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, module.Import(typeof(DateTime).GetMethod("get_Now"))));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, module.Import(typeof(DateTime).GetMethod("get_Ticks"))));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I8, 1000000));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Blt_S, dispatchTable[0]));
                */

                var rnd = new Random();
                for (int i = 0; i < 50; i++)
                {
                    var pattern = rnd.Next(4);
                    switch (pattern)
                    {
                        case 0:
                            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, rnd.Next()));
                            method.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
                            break;
                        case 1:
                            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                            method.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
                            break;
                        case 2:
                            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_R8, rnd.NextDouble()));
                            method.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
                            break;
                        case 3:
                            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, new string('x', rnd.Next(5, 20))));
                            method.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
                            break;
                    }
                }

                /*
                if (method.DebugScopes != null)
                    method.DebugScopes.Clear();
                if (method.DebugInfo != null && method.DebugInfo.Scopes != null)
                    method.DebugInfo.Scopes.Clear();
                */

                /*
                var fakeMethod = new MethodDefUser("__CorruptMethod_" + Guid.NewGuid().ToString("N"));
                fakeMethod.Attributes = MethodAttributes.PinvokeImpl | MethodAttributes.Static | MethodAttributes.Private;
                fakeMethod.ImplAttributes = MethodImplAttributes.PreserveSig | MethodImplAttributes.Unmanaged;
                fakeMethod.Signature = MethodSig.CreateStatic(method.Module.CorLibTypes.Void);
                method.DeclaringType.Methods.Add(fakeMethod);
                */

                foreach (var local in method.Body.Variables)
                {
                    var origType = local.Type;
                    // var fakeTypeSig = new GenericInstSig(new TypeSpecUser(), new TypeSig[] { origType, origType });
                    // local.Type = fakeTypeSig.ToTypeSig();
                    local.Type = origType;
                }

                var stateVar = new Local(module.CorLibTypes.Int32);
                method.Body.Variables.Add(stateVar);
                method.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Ldc_I4, 0));
                method.Body.Instructions.Insert(1, Instruction.Create(OpCodes.Stloc, stateVar));

                var switchLabel = Instruction.Create(OpCodes.Ldloc, stateVar);
                var switchTable = new List<Instruction>();
                for (int i = 0; i < dispatchTable.Count; i++)
                {
                    switchTable.Add(dispatchTable[i]);
                }
                var switchInst = Instruction.Create(OpCodes.Switch, switchTable.ToArray());
                method.Body.Instructions.Add(switchLabel);
                method.Body.Instructions.Add(switchInst);

                foreach (var label in dispatchTable)
                {
                    method.Body.Instructions.Add(label);
                }

                /*
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0xFFFFFFFF));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x7FFFFFFF));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Add_Ovf_Un));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldind_I4));
                */

                method.Body.MaxStack = (ushort)short.MaxValue;
            }
        }
    }
}