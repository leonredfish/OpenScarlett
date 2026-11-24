#pragma once

// MIT Microsoft XAudio2 2.9 (<xaudio2_xs.h>) public COM ABI header
// backed by XAudio2_9.dll (PCM16, IEEE Float, XMA2 0x0166, IMA-ADPCM 0x0011/0x0069, Opus 0x704F).

#include <cstddef>
#include <cstdint>
#include <unknwn.h>
#include <windows.h>

#define XA2_COMPAT_API __declspec(dllimport)
#define XA2_COMPAT_CALL __stdcall

constexpr uint16_t XA2_WAVE_FORMAT_PCM = 0x0001u;
constexpr uint16_t XA2_WAVE_FORMAT_IEEE_FLOAT = 0x0003u;
constexpr uint16_t XA2_WAVE_FORMAT_IMA_ADPCM = 0x0011u;
constexpr uint16_t XA2_WAVE_FORMAT_XBOX_ADPCM = 0x0069u;
constexpr uint16_t XA2_WAVE_FORMAT_XMA2 = 0x0166u;
constexpr uint16_t XA2_WAVE_FORMAT_OPUS = 0x704Fu;

constexpr uint32_t XAUDIO2_DEFAULT_CHANNELS = 0u;
constexpr uint32_t XAUDIO2_DEFAULT_SAMPLERATE = 0u;
constexpr uint32_t XAUDIO2_DEFAULT_PROCESSOR = 0x00000001u;
constexpr uint32_t XAUDIO2_COMMIT_NOW = 0u;
constexpr uint32_t XAUDIO2_END_OF_STREAM = 0x0040u;

#pragma pack(push, 1)
struct XA2_WAVEFORMATEX {
    uint16_t wFormatTag;
    uint16_t nChannels;
    uint32_t nSamplesPerSec;
    uint32_t nAvgBytesPerSec;
    uint16_t nBlockAlign;
    uint16_t wBitsPerSample;
    uint16_t cbSize;
};

struct XA2_XMA2WAVEFORMATEX {
    XA2_WAVEFORMATEX wfx;
    uint16_t NumStreams;
    uint32_t ChannelMask;
    uint32_t SamplesEncoded;
    uint32_t BytesPerBlock;
    uint32_t PlayBegin;
    uint32_t PlayLength;
    uint32_t LoopBegin;
    uint32_t LoopLength;
    uint8_t LoopCount;
    uint8_t EncoderVersion;
    uint16_t BlockCount;
};

struct XA2_IMAADPCMWAVEFORMAT {
    XA2_WAVEFORMATEX wfx;
    uint16_t wSamplesPerBlock;
};

struct XA2_OPUSWAVEFORMAT {
    XA2_WAVEFORMATEX wfx;
    uint16_t PreSkip;
    uint16_t Version;
};
#pragma pack(pop)

struct XAUDIO2_BUFFER {
    uint32_t Flags;
    uint32_t AudioBytes;
    const uint8_t* pAudioData;
    uint32_t PlayBegin;
    uint32_t PlayLength;
    uint32_t LoopBegin;
    uint32_t LoopLength;
    uint32_t LoopCount;
    void* pContext;
};

struct XAUDIO2_BUFFER_WMA {
    const uint32_t* pDecodedPacketCumulativeBytes;
    uint32_t PacketCount;
};

struct XAUDIO2_VOICE_STATE {
    void* pCurrentBufferContext;
    uint32_t BuffersQueued;
    uint64_t SamplesPlayed;
};

struct XAUDIO2_VOICE_DETAILS {
    uint32_t CreationFlags;
    uint32_t ActiveFlags;
    uint32_t InputChannels;
    uint32_t InputSampleRate;
};

struct IXAudio2Voice;

struct XAUDIO2_SEND_DESCRIPTOR {
    uint32_t Flags;
    IXAudio2Voice* pOutputVoice;
};

struct XAUDIO2_VOICE_SENDS {
    uint32_t SendCount;
    XAUDIO2_SEND_DESCRIPTOR* pSends;
};

struct XAUDIO2_PERFORMANCE_DATA {
    uint64_t AudioCyclesSinceLastQuery;
    uint64_t TotalCyclesSinceLastQuery;
    uint32_t MinimumCyclesPerQuantum;
    uint32_t MaximumCyclesPerQuantum;
    uint32_t MemoryUsageInBytes;
    uint32_t CurrentLatencyInSamples;
    uint32_t GlitchesSinceEngineStarted;
    uint32_t ActiveSourceVoiceCount;
    uint32_t TotalSourceVoiceCount;
    uint32_t ActiveSubmixVoiceCount;
    uint32_t ActiveResamplerCount;
    uint32_t ActiveMatrixMixCount;
    uint32_t ActiveXmaSourceVoices;
    uint32_t ActiveXmaStreams;
};

struct XAUDIO2_DEBUG_CONFIGURATION {
    uint32_t TraceMask;
    uint32_t BreakMask;
    int32_t LogThreadID;
    int32_t LogFileline;
    int32_t LogFunctionName;
    int32_t LogTiming;
};

struct IXAudio2VoiceCallback {
    virtual void XA2_COMPAT_CALL OnVoiceProcessingPassStart(uint32_t BytesRequired) = 0;
    virtual void XA2_COMPAT_CALL OnVoiceProcessingPassEnd() = 0;
    virtual void XA2_COMPAT_CALL OnStreamEnd() = 0;
    virtual void XA2_COMPAT_CALL OnBufferStart(void* pBufferContext) = 0;
    virtual void XA2_COMPAT_CALL OnBufferEnd(void* pBufferContext) = 0;
    virtual void XA2_COMPAT_CALL OnLoopEnd(void* pBufferContext) = 0;
    virtual void XA2_COMPAT_CALL OnVoiceError(void* pBufferContext, HRESULT Error) = 0;
};

struct IXAudio2EngineCallback {
    virtual void XA2_COMPAT_CALL OnProcessingPassStart() = 0;
    virtual void XA2_COMPAT_CALL OnProcessingPassEnd() = 0;
    virtual void XA2_COMPAT_CALL OnCriticalError(HRESULT Error) = 0;
};

constexpr float XAUDIO2_MAX_FILTER_ONEOVERQ = 1.5f;
constexpr float XAUDIO2_MAX_FILTER_FREQUENCY = 1.0f;

struct XAUDIO2_EFFECT_DESCRIPTOR {
    IUnknown* pEffect;
    BOOL InitialState;
    uint32_t OutputChannels;
};

struct XAUDIO2_EFFECT_CHAIN {
    uint32_t EffectCount;
    XAUDIO2_EFFECT_DESCRIPTOR* pEffectDescriptors;
};

enum XAUDIO2_FILTER_TYPE {
    LowPassFilter = 0,
    BandPassFilter = 1,
    HighPassFilter = 2,
    NotchFilter = 3,
};

struct XAUDIO2_FILTER_PARAMETERS {
    XAUDIO2_FILTER_TYPE Type;
    float Frequency;
    float OneOverQ;
};

// IMPORTANT: IXAudio2Voice must declare the complete Microsoft XAudio2 vtable
// (19 virtual methods) or every IXAudio2SourceVoice call from this guest
// dispatches into the wrong slot of OpenScarlett's XAudio2_9.dll shim
// (and of real Windows XAudio2), e.g. Start() -> GetEffectParameters(),
// SubmitSourceBuffer() -> GetFilterParameters() -> silent mix + bogus HRESULTs.
struct IXAudio2Voice {
    virtual void XA2_COMPAT_CALL GetVoiceDetails(XAUDIO2_VOICE_DETAILS* pVoiceDetails) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetOutputVoices(const XAUDIO2_VOICE_SENDS* pSendList) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetEffectChain(const XAUDIO2_EFFECT_CHAIN* pEffectChain) = 0;
    virtual HRESULT XA2_COMPAT_CALL EnableEffect(
        uint32_t EffectIndex, uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual HRESULT XA2_COMPAT_CALL DisableEffect(
        uint32_t EffectIndex, uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual void XA2_COMPAT_CALL GetEffectState(uint32_t EffectIndex, BOOL* pEnabled) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetEffectParameters(
        uint32_t EffectIndex,
        const void* pParameters,
        uint32_t ParametersByteSize,
        uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual HRESULT XA2_COMPAT_CALL GetEffectParameters(
        uint32_t EffectIndex, void* pParameters, uint32_t ParametersByteSize) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetFilterParameters(
        const XAUDIO2_FILTER_PARAMETERS* pParameters,
        uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual void XA2_COMPAT_CALL GetFilterParameters(XAUDIO2_FILTER_PARAMETERS* pParameters) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetOutputFilterParameters(
        IXAudio2Voice* pDestinationVoice,
        const XAUDIO2_FILTER_PARAMETERS* pParameters,
        uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual void XA2_COMPAT_CALL GetOutputFilterParameters(
        IXAudio2Voice* pDestinationVoice, XAUDIO2_FILTER_PARAMETERS* pParameters) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetVolume(float Volume, uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual void XA2_COMPAT_CALL GetVolume(float* pVolume) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetChannelVolumes(
        uint32_t Channels, const float* pVolumes, uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual void XA2_COMPAT_CALL GetChannelVolumes(uint32_t Channels, float* pVolumes) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetOutputMatrix(
        IXAudio2Voice* pDestinationVoice,
        uint32_t SourceChannels,
        uint32_t DestinationChannels,
        const float* pLevelMatrix,
        uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual void XA2_COMPAT_CALL GetOutputMatrix(
        IXAudio2Voice* pDestinationVoice,
        uint32_t SourceChannels,
        uint32_t DestinationChannels,
        float* pLevelMatrix) = 0;
    virtual void XA2_COMPAT_CALL DestroyVoice() = 0;
};

struct IXAudio2SourceVoice : public IXAudio2Voice {
    virtual HRESULT XA2_COMPAT_CALL Start(
        uint32_t Flags = 0, uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual HRESULT XA2_COMPAT_CALL Stop(
        uint32_t Flags = 0, uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual HRESULT XA2_COMPAT_CALL SubmitSourceBuffer(
        const XAUDIO2_BUFFER* pBuffer, const XAUDIO2_BUFFER_WMA* pBufferWMA = nullptr) = 0;
    virtual HRESULT XA2_COMPAT_CALL FlushSourceBuffers() = 0;
    virtual HRESULT XA2_COMPAT_CALL Discontinuity() = 0;
    virtual HRESULT XA2_COMPAT_CALL ExitLoop(uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual void XA2_COMPAT_CALL GetState(XAUDIO2_VOICE_STATE* pVoiceState, uint32_t Flags = 0) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetFrequencyRatio(
        float Ratio, uint32_t OperationSet = XAUDIO2_COMMIT_NOW) = 0;
    virtual void XA2_COMPAT_CALL GetFrequencyRatio(float* pRatio) = 0;
    virtual HRESULT XA2_COMPAT_CALL SetSourceSampleRate(uint32_t NewSourceSampleRate) = 0;
};

struct IXAudio2SubmixVoice : public IXAudio2Voice {};

struct IXAudio2MasteringVoice : public IXAudio2Voice {
    virtual HRESULT XA2_COMPAT_CALL GetChannelMask(uint32_t* pChannelMask) = 0;
};

struct __declspec(uuid("2B02E3CF-2E0B-4EC3-BE45-1B2A3FE7210D"))
IXAudio2 : public IUnknown {
    virtual HRESULT XA2_COMPAT_CALL RegisterForCallbacks(IXAudio2EngineCallback* pCallback) = 0;
    virtual void XA2_COMPAT_CALL UnregisterForCallbacks(IXAudio2EngineCallback* pCallback) = 0;
    virtual HRESULT XA2_COMPAT_CALL CreateSourceVoice(
        IXAudio2SourceVoice** ppSourceVoice,
        const XA2_WAVEFORMATEX* pSourceFormat,
        uint32_t Flags = 0,
        float MaxFrequencyRatio = 2.0f,
        IXAudio2VoiceCallback* pCallback = nullptr,
        const XAUDIO2_VOICE_SENDS* pSendList = nullptr,
        const void* pEffectChain = nullptr) = 0;
    virtual HRESULT XA2_COMPAT_CALL CreateSubmixVoice(
        IXAudio2SubmixVoice** ppSubmixVoice,
        uint32_t InputChannels,
        uint32_t InputSampleRate,
        uint32_t Flags = 0,
        uint32_t ProcessingStage = 0,
        const XAUDIO2_VOICE_SENDS* pSendList = nullptr,
        const void* pEffectChain = nullptr) = 0;
    virtual HRESULT XA2_COMPAT_CALL CreateMasteringVoice(
        IXAudio2MasteringVoice** ppMasteringVoice,
        uint32_t InputChannels = XAUDIO2_DEFAULT_CHANNELS,
        uint32_t InputSampleRate = XAUDIO2_DEFAULT_SAMPLERATE,
        uint32_t Flags = 0,
        const wchar_t* szDeviceId = nullptr,
        const void* pEffectChain = nullptr,
        uint32_t StreamCategory = 0) = 0;
    virtual HRESULT XA2_COMPAT_CALL StartEngine() = 0;
    virtual void XA2_COMPAT_CALL StopEngine() = 0;
    virtual HRESULT XA2_COMPAT_CALL CommitChanges(uint32_t OperationSet) = 0;
    virtual void XA2_COMPAT_CALL GetPerformanceData(XAUDIO2_PERFORMANCE_DATA* pPerfData) = 0;
    virtual void XA2_COMPAT_CALL SetDebugConfiguration(
        const XAUDIO2_DEBUG_CONFIGURATION* pDebugConfiguration,
        void* pReserved = nullptr) = 0;
};

extern "C" {

XA2_COMPAT_API HRESULT XA2_COMPAT_CALL XAudio2Create(
    IXAudio2** ppXAudio2,
    uint32_t Flags,
    uint32_t XAudio2Processor);

XA2_COMPAT_API HRESULT XA2_COMPAT_CALL OpenScarlettXAudio2RenderMixForTest(
    IXAudio2* pXAudio2,
    float* out_frames,
    uint32_t frame_count);

}  // extern "C"
